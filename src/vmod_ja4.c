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
 *
 * Uses an SSL_CTX ex_data new_func callback so the msg callback is
 * installed automatically at SSL_CTX_new() time -- no timing issues.
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
#define RAW_MAX_CIPHERS   128
#define RAW_MAX_EXTS       64
#define RAW_MAX_SIG_ALGS   64
#define RAW_MAX_ALPN       64

/* --- Parsed Client Hello stored per connection --- */
struct ja4_parsed {
	uint16_t	tls_version;
	uint8_t		has_sni;
	uint8_t		nciphers;
	uint8_t		nexts;
	uint8_t		nsigs;
	char		alpn_first;
	char		alpn_last;
	uint16_t	data[];
};

/* --- OpenSSL ex_data and automatic callback installation --- */
static int ja4_ssl_ex_idx = -1;
static int ja4_conn_cache_ex_idx = -1;
static pthread_once_t ja4_once_ctrl = PTHREAD_ONCE_INIT;

static void ja4_msg_cb(int, int, int, const void *, size_t, SSL *, void *);

static void
ja4_ex_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp)
{
	(void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
	free(ptr);
}

struct ja4_conn_cache {
	unsigned	 computed;
	const char	*ptr[4];
};

static void
ja4_conn_cache_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp)
{
	struct ja4_conn_cache *conn_cache;
	unsigned i;

	(void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
	conn_cache = ptr;
	if (conn_cache == NULL)
		return;
	for (i = 0; i < 4; i++) {
		if ((conn_cache->computed & (1u << i)) != 0 &&
		    conn_cache->ptr[i] != NULL)
			free((void *)conn_cache->ptr[i]);
	}
	free(conn_cache);
}

/*
 * Called by OpenSSL each time SSL_CTX_new() creates a context.
 * Installs our msg callback before any handshake can occur.
 */
static void
ja4_ctx_new_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp)
{
	(void)ptr; (void)ad; (void)idx; (void)argl; (void)argp;
	SSL_CTX_set_msg_callback(parent, ja4_msg_cb);
}

static void
ja4_init_once(void)
{
	ja4_ssl_ex_idx = SSL_get_ex_new_index(0, NULL,
	    NULL, NULL, ja4_ex_free_cb);
	ja4_conn_cache_ex_idx = SSL_get_ex_new_index(0, NULL,
	    NULL, NULL, ja4_conn_cache_free_cb);
	(void)SSL_CTX_get_ex_new_index(0, NULL,
	    ja4_ctx_new_cb, NULL, NULL);
}

#define BE16(p)    ((uint16_t)(p)[0] << 8 | (p)[1])
#define HEX_LOW(x) ("0123456789abcdef"[(x) & 0xf])
#define JA4_ZERO_HASH "000000000000"

/* --- Client Hello parser (msg callback) --- */
static void
ja4_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
	const unsigned char *p = buf;
	struct ja4_parsed *parsed;
	uint16_t ciphers[RAW_MAX_CIPHERS], exts[RAW_MAX_EXTS];
	uint16_t sigs[RAW_MAX_SIG_ALGS];
	unsigned nciphers, nexts, nsigs;
	uint16_t legacy_version, tls_version;
	int has_sni;
	char alpn_first, alpn_last;
	size_t off, body_len, cslen, ext_len, ext_end, i;

	(void)version; (void)arg;
	if (write_p != 0 || content_type != SSL3_RT_HANDSHAKE ||
	    len < 4 || len > CLIENT_HELLO_MAX_LEN ||
	    p[0] != SSL3_MT_CLIENT_HELLO)
		return;
	body_len = (size_t)p[1] << 16 | (size_t)p[2] << 8 | p[3];
	if (body_len > CLIENT_HELLO_MAX_LEN - 4 ||
	    len < 4 + body_len || body_len < 2 + 32 + 1)
		return;

	off = 4;
	legacy_version = BE16(p + off);
	off += 2 + 32;

	if (off >= len) return;
	if ((size_t)p[off] > len - off - 1)
		return;
	off += 1 + (size_t)p[off];

	if (off + 2 > len) return;
	cslen = BE16(p + off); off += 2;
	if (off + cslen > len)
		return;

	nciphers = 0;
	for (i = 0; i + 2 <= cslen; i += 2) {
		uint16_t c = BE16(p + off + i);
		if (!IS_GREASE_TLS(c) && nciphers < RAW_MAX_CIPHERS)
			ciphers[nciphers++] = c;
	}
	off += cslen;

	if (off >= len) return;
	if ((size_t)p[off] > len - off - 1)
		return;
	off += 1 + (size_t)p[off];

	if (off + 2 > len) return;
	ext_len = BE16(p + off); off += 2;
	ext_end = off + ext_len;
	if (ext_end > len)
		return;

	has_sni = 0;
	nexts = nsigs = 0;
	alpn_first = alpn_last = '0';
	tls_version = legacy_version;

	while (off + 4 <= ext_end) {
		uint16_t etype = BE16(p + off);
		uint16_t elen  = BE16(p + off + 2);
		off += 4;
		if (off + elen > ext_end)
			break;

		if (!IS_GREASE_TLS(etype) && nexts < RAW_MAX_EXTS)
			exts[nexts++] = etype;

		if (etype == TLSEXT_TYPE_server_name) {
			has_sni = 1;
		} else if (etype == TLSEXT_TYPE_signature_algorithms &&
		    elen >= 2 && elen <= RAW_MAX_SIG_ALGS * 2 + 2) {
			uint16_t salen = BE16(p + off);
			for (i = 2; i + 2 <= 2 + (size_t)salen &&
			    i + 2 <= (size_t)elen; i += 2) {
				uint16_t sa = BE16(p + off + i);
				if (!IS_GREASE_TLS(sa) &&
				    nsigs < RAW_MAX_SIG_ALGS)
					sigs[nsigs++] = sa;
			}
		} else if (etype == TLSEXT_TYPE_alpn &&
		    elen >= 3 && elen <= RAW_MAX_ALPN) {
			size_t ll = BE16(p + off);
			unsigned plen = p[off + 2];
			const unsigned char *ap = p + off + 3;
			if (plen > 0 && ll > 0 && plen <= ll - 1 &&
			    3 + plen <= (size_t)elen) {
				if (IS_ASCII_ALNUM(ap[0]) &&
				    IS_ASCII_ALNUM(ap[plen - 1])) {
					alpn_first = (char)ap[0];
					alpn_last  = (char)ap[plen - 1];
				} else {
					alpn_first = HEX_LOW(ap[0] >> 4);
					alpn_last  = HEX_LOW(ap[plen - 1]);
				}
			}
		} else if (etype == TLSEXT_TYPE_supported_versions &&
		    elen >= 2 && elen <= 32) {
			const unsigned char *sv = p + off;
			uint16_t vmax = 0;
			size_t svoff = (elen >= 3 &&
			    (size_t)sv[0] == elen - 1) ? 1 : 0;
			for (; svoff + 2 <= (size_t)elen; svoff += 2) {
				uint16_t v = BE16(sv + svoff);
				if (!IS_GREASE_TLS(v) && v > vmax)
					vmax = v;
			}
			if (vmax != 0)
				tls_version = vmax;
		}
		off += elen;
	}

	parsed = malloc(sizeof(*parsed) +
	    ((size_t)nciphers + nexts + nsigs) * sizeof(uint16_t));
	if (parsed == NULL)
		return;
	parsed->tls_version = tls_version;
	parsed->has_sni = has_sni;
	parsed->nciphers = (uint8_t)nciphers;
	parsed->nexts = (uint8_t)nexts;
	parsed->nsigs = (uint8_t)nsigs;
	parsed->alpn_first = alpn_first;
	parsed->alpn_last = alpn_last;
	memcpy(parsed->data, ciphers, nciphers * sizeof(uint16_t));
	memcpy(parsed->data + nciphers, exts, nexts * sizeof(uint16_t));
	memcpy(parsed->data + nciphers + nexts, sigs,
	    nsigs * sizeof(uint16_t));
	free(SSL_get_ex_data(ssl, ja4_ssl_ex_idx));
	SSL_set_ex_data(ssl, ja4_ssl_ex_idx, parsed);
}

/* --- JA4 variant bits and per-connection cache --- */
#define JA4_SORTED   0x01u
#define JA4_HASHED   0x02u
#define JA4_MAIN     (JA4_SORTED | JA4_HASHED)
#define JA4_R        (JA4_SORTED)
#define JA4_O        (JA4_HASHED)
#define JA4_RO       0u
#define JA4_HASH_LEN    12
#define JA4_HASH_BUF    13
#define JA4_CAP(x) ((x) > 99 ? 99 : (unsigned)(x))

/* --- JA4 helpers --- */
static int
cmp_uint16(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
	return ((x > y) - (x < y));
}

static size_t
hex_list(char *buf, size_t sz, size_t off,
    const uint16_t *a, unsigned n)
{
	unsigned i;

	for (i = 0; i < n && off + 5 < sz; i++) {
		if (i > 0)
			buf[off++] = ',';
		buf[off++] = HEX_LOW(a[i] >> 12);
		buf[off++] = HEX_LOW(a[i] >> 8);
		buf[off++] = HEX_LOW(a[i] >> 4);
		buf[off++] = HEX_LOW(a[i]);
	}
	return (off);
}

/*
 * SHA-256 of one or two comma-separated hex-uint16 lists joined
 * by underscore, truncated to 12 hex chars.
 */
static void
ja4_hash_lists(const uint16_t *a, unsigned na,
    const uint16_t *b, unsigned nb, char out[JA4_HASH_BUF])
{
	char tmp[1536];
	size_t off;
	unsigned char digest[32];
	unsigned i;

	if (na == 0 && nb == 0) {
		memcpy(out, JA4_ZERO_HASH, JA4_HASH_BUF);
		return;
	}
	off = hex_list(tmp, sizeof(tmp), 0, a, na);
	if (nb > 0) {
		if (na > 0 && off < sizeof(tmp))
			tmp[off++] = '_';
		off = hex_list(tmp, sizeof(tmp), off, b, nb);
	}
	if (EVP_Digest(tmp, off, digest, NULL, EVP_sha256(), NULL) != 1) {
		memcpy(out, JA4_ZERO_HASH, JA4_HASH_BUF);
		return;
	}
	for (i = 0; i < JA4_HASH_LEN / 2; i++) {
		out[2 * i]     = HEX_LOW(digest[i] >> 4);
		out[2 * i + 1] = HEX_LOW(digest[i]);
	}
	out[JA4_HASH_LEN] = '\0';
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
	struct ja4_conn_cache *conn_cache;
	SSL *ssl;
	struct ja4_parsed *parsed;
	const char *ret = NULL;
	int do_sort = (variant & JA4_SORTED) != 0;
	int do_hash = (variant & JA4_HASHED) != 0;
	uint16_t ciphers[RAW_MAX_CIPHERS], exts[RAW_MAX_EXTS];
	const uint16_t *pexts, *sigs;
	unsigned nciphers, nexts, nsigs, ext_total, i;
	const char *ver;
	char part_a[16];

	assert(variant < 4);

	ssl = (SSL *)VTLS_tls_ctx(ctx);
	if (ssl == NULL)
		return (NULL);
	if (ja4_ssl_ex_idx < 0) {
		VSLb(ctx->vsl, SLT_Debug, "ja4: ex_data not allocated");
		return (NULL);
	}
	parsed = SSL_get_ex_data(ssl, ja4_ssl_ex_idx);
	if (parsed == NULL)
		return (NULL);

	/* Clamp counts from parsed so we never overflow local buffers or
	 * read past parsed->data (e.g. if ex_data was corrupted). */
	nciphers = parsed->nciphers;
	if (nciphers > RAW_MAX_CIPHERS)
		nciphers = RAW_MAX_CIPHERS;
	ext_total = parsed->nexts;
	if (ext_total > RAW_MAX_EXTS)
		ext_total = RAW_MAX_EXTS;
	nsigs = parsed->nsigs;
	if (nsigs > RAW_MAX_SIG_ALGS)
		nsigs = RAW_MAX_SIG_ALGS;

	/* Return cached result for this connection if already computed. */
	if (ja4_conn_cache_ex_idx >= 0) {
		conn_cache = SSL_get_ex_data(ssl, ja4_conn_cache_ex_idx);
		if (conn_cache != NULL &&
		    (conn_cache->computed & (1u << variant)) &&
		    conn_cache->ptr[variant] != NULL)
			return (WS_Printf(ctx->ws, "%s",
			    conn_cache->ptr[variant]));
	}

	memcpy(ciphers, parsed->data, nciphers * sizeof(uint16_t));

	pexts = parsed->data + nciphers;
	nexts = 0;
	for (i = 0; i < ext_total; i++) {
		if (do_sort && (pexts[i] == TLSEXT_TYPE_server_name ||
		    pexts[i] == TLSEXT_TYPE_alpn))
			continue;
		if (nexts < RAW_MAX_EXTS)
			exts[nexts++] = pexts[i];
	}

	sigs = parsed->data + nciphers + ext_total;

	switch (parsed->tls_version) {
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

	snprintf(part_a, sizeof(part_a), "t%s%c%02u%02u%c%c",
	    ver, parsed->has_sni ? 'd' : 'i',
	    JA4_CAP(nciphers), JA4_CAP(ext_total),
	    parsed->alpn_first, parsed->alpn_last);

	if (do_sort) {
		if (nciphers > 1)
			qsort(ciphers, nciphers, sizeof(uint16_t),
			    cmp_uint16);
		if (nexts > 1)
			qsort(exts, nexts, sizeof(uint16_t), cmp_uint16);
	}

	if (do_hash) {
		char ch[JA4_HASH_BUF], eh[JA4_HASH_BUF];
		ja4_hash_lists(ciphers, nciphers, NULL, 0, ch);
		ja4_hash_lists(exts, nexts, sigs, nsigs, eh);
		ret = WS_Printf(ctx->ws, "%s_%s_%s", part_a, ch, eh);
	} else {
		char buf[4096];
		size_t off = (size_t)snprintf(buf, sizeof(buf),
		    "%s_", part_a);
		off = hex_list(buf, sizeof(buf), off, ciphers, nciphers);
		if (off + 1 < sizeof(buf))
			buf[off++] = '_';
		off = hex_list(buf, sizeof(buf), off, exts, nexts);
		if (nsigs > 0 && off + 1 < sizeof(buf)) {
			buf[off++] = '_';
			off = hex_list(buf, sizeof(buf), off, sigs, nsigs);
		}
		buf[off] = '\0';
		ret = WS_Printf(ctx->ws, "%s", buf);
	}
	if (ret == NULL)
		VSLb(ctx->vsl, SLT_Debug, "ja4: workspace overflow");

	/* Store in connection-level cache for reuse on same TLS connection. */
	if (ja4_conn_cache_ex_idx >= 0 && ret != NULL) {
		char *cached;

		conn_cache = SSL_get_ex_data(ssl, ja4_conn_cache_ex_idx);
		cached = strdup(ret);
		if (cached != NULL) {
			if (conn_cache == NULL) {
				conn_cache = calloc(1, sizeof(*conn_cache));
				if (conn_cache == NULL || SSL_set_ex_data(ssl,
				    ja4_conn_cache_ex_idx, conn_cache) != 1) {
					free(conn_cache);
					free(cached);
					return (ret);
				}
			}
			if (conn_cache->ptr[variant] != NULL)
				free((void *)conn_cache->ptr[variant]);
			conn_cache->ptr[variant] = cached;
			conn_cache->computed |= (1u << variant);
		}
	}

	return (ret);
}

/* --- VCL entry points --- */
#define JA4_FUNC(name, variant)			\
VCL_STRING vmod_##name(VRT_CTX) {		\
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);	\
	return (ja4_compute(ctx, variant));	\
}

JA4_FUNC(ja4,    JA4_MAIN)
JA4_FUNC(ja4_r,  JA4_R)
JA4_FUNC(ja4_o,  JA4_O)
JA4_FUNC(ja4_ro, JA4_RO)
