/*-
 * JA4 TLS Client Fingerprinting VMOD.
 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * Variants: ja4 (sorted+hashed), ja4_r (sorted+raw),
 * ja4_o (original+hashed), ja4_ro (original+raw).
 *
 * Parses raw Client Hello wire bytes via OpenSSL msg callback,
 * not OpenSSL's parsed representation (which drops unknown exts).
 * Requires Varnish with client-side TLS exporting VTLS_tls_ctx().
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "cache/cache.h"
#include "vcl.h"
#include "vcc_ja4_if.h"

/* Varnish-internal (cache_client_ssl.c); keep in sync when upgrading. */
const SSL *VTLS_tls_ctx(const struct vrt_ctx *ctx);

#ifndef SSL3_RT_HANDSHAKE
#define SSL3_RT_HANDSHAKE 22
#endif
#ifndef SSL3_MT_CLIENT_HELLO
#define SSL3_MT_CLIENT_HELLO 1
#endif

#define TLSEXT_TYPE_server_name            0
#define TLSEXT_TYPE_signature_algorithms   13
#define TLSEXT_TYPE_alpn                   16
#define TLSEXT_TYPE_supported_versions     43

#define IS_GREASE_TLS(x) \
	((((x) & 0x0f0f) == 0x0a0a) && (((x) & 0xff) == (((x) >> 8) & 0xff)))
#define IS_ASCII_ALNUM(c) \
	(((c) >= '0' && (c) <= '9') || \
	 ((c) >= 'A' && (c) <= 'Z') || \
	 ((c) >= 'a' && (c) <= 'z'))
#define CLIENT_HELLO_MAX_LEN 16384

/* --- Client Hello capture via msg callback --- */

struct ja4_capture {
	size_t		len;
	unsigned char	buf[];
};

static int ja4_ssl_ex_idx = -1;
static int ja4_ctx_ex_idx = -1;
static pthread_once_t ja4_once_ctrl = PTHREAD_ONCE_INIT;

static void
ja4_ex_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp)
{
	(void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
	free(ptr);
}

static void
ja4_init_once(void)
{
	ja4_ssl_ex_idx = SSL_get_ex_new_index(0, NULL,
	    NULL, NULL, ja4_ex_free_cb);
	ja4_ctx_ex_idx = SSL_CTX_get_ex_new_index(0, NULL,
	    NULL, NULL, NULL);
}

static void
ja4_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
	struct ja4_capture *cap;

	(void)version; (void)arg;
	if (write_p != 0 || content_type != SSL3_RT_HANDSHAKE ||
	    len < 1 || ((const unsigned char *)buf)[0] != SSL3_MT_CLIENT_HELLO)
		return;
	if (len > CLIENT_HELLO_MAX_LEN || ja4_ssl_ex_idx < 0)
		return;
	cap = malloc(sizeof(*cap) + len);
	if (cap == NULL)
		return;
	cap->len = len;
	memcpy(cap->buf, buf, len);
	free(SSL_get_ex_data(ssl, ja4_ssl_ex_idx));
	SSL_set_ex_data(ssl, ja4_ssl_ex_idx, cap);
}

/* --- JA4 variant bits and per-request cache --- */

#define JA4_SORTED   0x01u
#define JA4_HASHED   0x02u
#define JA4_MAIN     (JA4_SORTED | JA4_HASHED)
#define JA4_R        (JA4_SORTED)
#define JA4_O        (JA4_HASHED)
#define JA4_RO       0u
#define JA4_HASH_LEN    12
#define JA4_HASH_BUF    13
#define JA4_COUNT_CAP   99
#define JA4_CAP(x) ((x) > JA4_COUNT_CAP ? JA4_COUNT_CAP : (unsigned)(x))

struct ja4_task_cache {
	const char	*result[4];
	unsigned	 computed;
	const char	*reason;
};

static const void *ja4_cache_id = &ja4_cache_id;

/* --- Raw Client Hello fields --- */

#define RAW_MAX_CIPHERS   128
#define RAW_MAX_EXTS       64
#define RAW_MAX_SIG_ALGS   64
#define RAW_MAX_ALPN       64

struct raw_client_hello {
	uint16_t	legacy_version;
	int		has_sni;
	unsigned char	ciphers[RAW_MAX_CIPHERS * 2];
	size_t		cipher_len;
	uint16_t	ext_types[RAW_MAX_EXTS];
	size_t		ext_count;
	unsigned char	sig_algs[RAW_MAX_SIG_ALGS * 2 + 2];
	size_t		sig_algs_len;
	unsigned char	supported_versions[32];
	size_t		supported_versions_len;
	unsigned char	alpn[RAW_MAX_ALPN];
	size_t		alpn_len;
};

static inline uint16_t
be16dec(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8 | p[1]);
}

/* --- JA4 helpers --- */

static int
cmp_uint16(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
	return ((x > y) - (x < y));
}

static char
hex_low(unsigned x)
{
	return ("0123456789abcdef"[x & 0xf]);
}

static void
uint16_to_hex(char *out, uint16_t v)
{
	out[0] = hex_low(v >> 12); out[1] = hex_low(v >> 8);
	out[2] = hex_low(v >> 4);  out[3] = hex_low(v);
	out[4] = '\0';
}

static int
hash_hex_list(EVP_MD_CTX *md_ctx, const uint16_t *a, unsigned n)
{
	char hex[5];
	unsigned i;

	for (i = 0; i < n; i++) {
		if (i > 0 && EVP_DigestUpdate(md_ctx, ",", 1) != 1)
			return (-1);
		uint16_to_hex(hex, a[i]);
		if (EVP_DigestUpdate(md_ctx, hex, 4) != 1)
			return (-1);
	}
	return (0);
}

/*
 * SHA-256 of one or two comma-separated hex-uint16 lists joined
 * by underscore, truncated to 12 hex chars.
 */
static void
ja4_hash_lists(const uint16_t *a, unsigned na,
    const uint16_t *b, unsigned nb, char out[JA4_HASH_BUF])
{
	EVP_MD_CTX *md_ctx;
	unsigned char digest[32];
	unsigned int dlen;
	unsigned i;

	if (na == 0 && nb == 0) {
		memcpy(out, "000000000000", JA4_HASH_BUF);
		return;
	}
	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL)
		goto fail;
	if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1)
		goto fail;
	if (hash_hex_list(md_ctx, a, na) != 0)
		goto fail;
	if (nb > 0) {
		if (na > 0 && EVP_DigestUpdate(md_ctx, "_", 1) != 1)
			goto fail;
		if (hash_hex_list(md_ctx, b, nb) != 0)
			goto fail;
	}
	if (EVP_DigestFinal_ex(md_ctx, digest, &dlen) != 1 || dlen != 32)
		goto fail;
	EVP_MD_CTX_free(md_ctx);
	for (i = 0; i < JA4_HASH_LEN / 2; i++) {
		out[2 * i]     = hex_low(digest[i] >> 4);
		out[2 * i + 1] = hex_low(digest[i]);
	}
	out[JA4_HASH_LEN] = '\0';
	return;
fail:
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	memcpy(out, "000000000000", JA4_HASH_BUF);
}

static size_t
hex_list(char *buf, size_t sz, size_t off,
    const uint16_t *a, unsigned n)
{
	char hex[5];
	unsigned i;

	for (i = 0; i < n && off + 5 < sz; i++) {
		if (i > 0)
			buf[off++] = ',';
		uint16_to_hex(hex, a[i]);
		memcpy(buf + off, hex, 4);
		off += 4;
	}
	return (off);
}

/* --- VCL event handler --- */

int
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	(void)ctx; (void)priv;
	if (e == VCL_EVENT_WARM)
		pthread_once(&ja4_once_ctrl, ja4_init_once);
	return (0);
}

/* --- JA4 computation --- */

static VCL_STRING
ja4_compute(VRT_CTX, unsigned variant)
{
	struct vmod_priv *task_priv;
	struct ja4_task_cache *cache;
	SSL *ssl;
	SSL_CTX *sctx;
	struct ja4_capture *cap;
	struct raw_client_hello raw;
	int do_sort = (variant & JA4_SORTED) != 0;
	int do_hash = (variant & JA4_HASHED) != 0;
	uint16_t ciphers[RAW_MAX_CIPHERS], exts[RAW_MAX_EXTS];
	uint16_t sigs[RAW_MAX_SIG_ALGS];
	unsigned nciphers, ext_total, nexts, nsigs;
	const char *ver;
	char part_a[16];
	uint16_t wire;
	char alpn_first, alpn_last;
	size_t i, off, body_len, cslen, ext_len, ext_end;

	assert(variant < 4);

	task_priv = VRT_priv_task(ctx, ja4_cache_id);
	if (task_priv == NULL)
		return (NULL);
	cache = task_priv->priv;
	if (cache != NULL && (cache->computed & (1u << variant)))
		return (cache->result[variant]);
	if (cache == NULL) {
		cache = WS_Alloc(ctx->ws, sizeof(*cache));
		if (cache == NULL)
			return (NULL);
		memset(cache, 0, sizeof(*cache));
		task_priv->priv = cache;
	}

	/* VTLS_tls_ctx() is const; SSL_get_ex_data() needs mutable. */
	ssl = (SSL *)VTLS_tls_ctx(ctx);
	if (ssl == NULL) {
		cache->reason = "no_tls";
		goto done;
	}
	pthread_once(&ja4_once_ctrl, ja4_init_once);

	/*
	 * Install msg callback once per SSL_CTX.  Benign TOCTOU race:
	 * concurrent workers setting the same pointer is idempotent.
	 */
	sctx = SSL_get_SSL_CTX(ssl);
	if (sctx != NULL && ja4_ctx_ex_idx >= 0 &&
	    SSL_CTX_get_ex_data(sctx, ja4_ctx_ex_idx) == NULL) {
		SSL_CTX_set_msg_callback(sctx, ja4_msg_cb);
		SSL_CTX_set_ex_data(sctx, ja4_ctx_ex_idx, (void *)1);
	}

	if (ja4_ssl_ex_idx < 0) {
		cache->reason = "no_ex_data";
		VSLb(ctx->vsl, SLT_Debug, "ja4: ex_data not allocated");
		goto done;
	}
	cap = SSL_get_ex_data(ssl, ja4_ssl_ex_idx);
	if (cap == NULL) {
		cache->reason = "no_capture";
		goto done;
	}

	/* --- Parse Client Hello --- */
	memset(&raw, 0, sizeof(raw));
	if (cap->len < 4 || cap->len > CLIENT_HELLO_MAX_LEN ||
	    cap->buf[0] != SSL3_MT_CLIENT_HELLO)
		goto parse_fail;
	body_len = (size_t)cap->buf[1] << 16 |
	    (size_t)cap->buf[2] << 8 | cap->buf[3];
	if (body_len > CLIENT_HELLO_MAX_LEN - 4 ||
	    cap->len < 4 + body_len || body_len < 2 + 32 + 1)
		goto parse_fail;

	off = 4;
	raw.legacy_version = be16dec(cap->buf + off);
	off += 2 + 32;					/* version + random */

	if (off >= cap->len) goto parse_fail;		/* session_id */
	off += 1 + (size_t)cap->buf[off];

	if (off + 2 > cap->len) goto parse_fail;	/* cipher_suites */
	cslen = be16dec(cap->buf + off); off += 2;
	if (cslen > sizeof(raw.ciphers) || off + cslen > cap->len)
		goto parse_fail;
	memcpy(raw.ciphers, cap->buf + off, cslen);
	raw.cipher_len = cslen;
	off += cslen;

	if (off >= cap->len) goto parse_fail;		/* compression */
	off += 1 + (size_t)cap->buf[off];

	if (off + 2 > cap->len) goto parse_fail;	/* extensions */
	ext_len = be16dec(cap->buf + off); off += 2;
	ext_end = off + ext_len;
	if (ext_end > cap->len)
		goto parse_fail;

	while (off + 4 <= ext_end) {
		uint16_t etype = be16dec(cap->buf + off);
		uint16_t elen  = be16dec(cap->buf + off + 2);
		off += 4;
		if (off + elen > ext_end)
			break;
		if (raw.ext_count < RAW_MAX_EXTS)
			raw.ext_types[raw.ext_count++] = etype;
		if (etype == TLSEXT_TYPE_server_name)
			raw.has_sni = 1;
		else if (etype == TLSEXT_TYPE_signature_algorithms &&
		    elen >= 2 && elen <= sizeof(raw.sig_algs)) {
			memcpy(raw.sig_algs, cap->buf + off, elen);
			raw.sig_algs_len = elen;
		} else if (etype == TLSEXT_TYPE_alpn &&
		    elen >= 2 && elen <= sizeof(raw.alpn)) {
			memcpy(raw.alpn, cap->buf + off, elen);
			raw.alpn_len = elen;
		} else if (etype == TLSEXT_TYPE_supported_versions &&
		    elen >= 2 && elen <= sizeof(raw.supported_versions)) {
			memcpy(raw.supported_versions, cap->buf + off, elen);
			raw.supported_versions_len = elen;
		}
		off += elen;
	}

	/* --- TLS version: prefer supported_versions over legacy --- */
	wire = raw.legacy_version;
	if (raw.supported_versions_len >= 2) {
		const unsigned char *sv = raw.supported_versions;
		uint16_t vmax = 0;
		off = (raw.supported_versions_len >= 3 &&
		    (size_t)sv[0] == raw.supported_versions_len - 1)
		    ? 1 : 0;
		for (; off + 2 <= raw.supported_versions_len; off += 2) {
			uint16_t v = be16dec(sv + off);
			if (!IS_GREASE_TLS(v) && v > vmax)
				vmax = v;
		}
		if (vmax != 0)
			wire = vmax;
	}
	switch (wire) {
	case 0x0304: ver = "13"; break;
	case 0x0303: ver = "12"; break;
	case 0x0302: ver = "11"; break;
	case 0x0301: ver = "10"; break;
	case 0x0300: ver = "s3"; break;
	case 0x0002: ver = "s2"; break;
	case 0xfeff: ver = "d1"; break;
	case 0xfefd: ver = "d2"; break;
	case 0xfefc: ver = "d3"; break;
	default:     ver = "00"; break;
	}

	nciphers = 0;
	for (i = 0; i + 2 <= raw.cipher_len; i += 2) {
		uint16_t c = be16dec(raw.ciphers + i);
		if (!IS_GREASE_TLS(c) && nciphers < RAW_MAX_CIPHERS)
			ciphers[nciphers++] = c;
	}

	ext_total = nexts = 0;
	for (i = 0; i < raw.ext_count; i++) {
		uint16_t et = raw.ext_types[i];
		if (IS_GREASE_TLS(et))
			continue;
		ext_total++;
		if (do_sort && (et == TLSEXT_TYPE_server_name ||
		    et == TLSEXT_TYPE_alpn))
			continue;
		if (nexts < RAW_MAX_EXTS)
			exts[nexts++] = et;
	}

	alpn_first = alpn_last = '0';
	if (raw.alpn_len >= 3) {
		unsigned plen = raw.alpn[2];
		const unsigned char *p = raw.alpn + 3;
		size_t ll = be16dec(raw.alpn);
		if (plen > 0 && ll > 0 && plen <= ll - 1 &&
		    3 + plen <= raw.alpn_len) {
			if (IS_ASCII_ALNUM(p[0]) &&
			    IS_ASCII_ALNUM(p[plen - 1])) {
				alpn_first = (char)p[0];
				alpn_last  = (char)p[plen - 1];
			} else {
				alpn_first = hex_low(p[0] >> 4);
				alpn_last = hex_low(p[plen - 1]);
			}
		}
	}

	snprintf(part_a, sizeof(part_a), "t%s%c%02u%02u%c%c",
	    ver, raw.has_sni ? 'd' : 'i',
	    JA4_CAP(nciphers), JA4_CAP(ext_total),
	    alpn_first, alpn_last);

	if (do_sort) {
		if (nciphers > 1)
			qsort(ciphers, nciphers, sizeof(uint16_t), cmp_uint16);
		if (nexts > 1)
			qsort(exts, nexts, sizeof(uint16_t), cmp_uint16);
	}

	nsigs = 0;
	if (raw.sig_algs_len >= 2) {
		uint16_t salen = be16dec(raw.sig_algs);
		for (i = 2; i + 2 <= 2 + (size_t)salen &&
		    i + 2 <= raw.sig_algs_len; i += 2) {
			uint16_t sa = be16dec(raw.sig_algs + i);
			if (!IS_GREASE_TLS(sa) && nsigs < RAW_MAX_SIG_ALGS)
				sigs[nsigs++] = sa;
		}
	}

	if (do_hash) {
		char ch[JA4_HASH_BUF], eh[JA4_HASH_BUF];
		ja4_hash_lists(ciphers, nciphers, NULL, 0, ch);
		ja4_hash_lists(exts, nexts, sigs, nsigs, eh);
		cache->result[variant] = WS_Printf(ctx->ws,
		    "%s_%s_%s", part_a, ch, eh);
	} else {
		char buf[4096];
		off = (size_t)snprintf(buf, sizeof(buf), "%s_", part_a);
		off = hex_list(buf, sizeof(buf), off, ciphers, nciphers);
		if (off + 1 < sizeof(buf))
			buf[off++] = '_';
		off = hex_list(buf, sizeof(buf), off, exts, nexts);
		if (nsigs > 0 && off + 1 < sizeof(buf)) {
			buf[off++] = '_';
			off = hex_list(buf, sizeof(buf), off, sigs, nsigs);
		}
		buf[off] = '\0';
		cache->result[variant] = WS_Printf(ctx->ws, "%s", buf);
	}
	if (cache->result[variant] == NULL)
		VSLb(ctx->vsl, SLT_Debug, "ja4: workspace overflow");
	cache->reason = "";
	goto done;

parse_fail:
	cache->reason = "parse_fail";
	VSLb(ctx->vsl, SLT_Debug,
	    "ja4: Client Hello parse failed (len=%zu)", cap->len);
done:
	cache->computed |= (1u << variant);
	return (cache->result[variant]);
}

VCL_STRING
vmod_ja4(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return (ja4_compute(ctx, JA4_MAIN));
}

VCL_STRING
vmod_ja4_r(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return (ja4_compute(ctx, JA4_R));
}

VCL_STRING
vmod_ja4_o(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return (ja4_compute(ctx, JA4_O));
}

VCL_STRING
vmod_ja4_ro(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return (ja4_compute(ctx, JA4_RO));
}

VCL_STRING
vmod_reason(VRT_CTX)
{
	struct vmod_priv *task_priv;
	struct ja4_task_cache *cache;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	(void)ja4_compute(ctx, JA4_MAIN);
	task_priv = VRT_priv_task(ctx, ja4_cache_id);
	if (task_priv == NULL || task_priv->priv == NULL)
		return ("no_priv");
	cache = task_priv->priv;
	return (cache->reason != NULL ? cache->reason : "");
}
