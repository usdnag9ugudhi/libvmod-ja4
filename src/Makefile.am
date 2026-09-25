AM_CFLAGS = $(VCACHEAPI_CFLAGS)

# Modules

vmod_LTLIBRARIES = \
	libvmod_ja4.la

# OpenSSL copies our msg callback into every SSL, beyond the reach of
# fini, so never let dlclose() unmap us.
libvmod_ja4_la_LDFLAGS = $(VMOD_LDFLAGS) $(LIBSSL_LIBS) -Wl,-z,nodelete

libvmod_ja4_la_SOURCES = \
	vmod_ja4.c

nodist_libvmod_ja4_la_SOURCES = \
	vcc_ja4_if.c \
	vcc_ja4_if.h

@BUILD_VMOD_JA4@

DISTCLEANFILES = vmod_vcs_version.txt

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VCACHE_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VCACHE_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = vtest -v -E$(VTESTEXT)
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VCACHEAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VCACHEAPI_VMODDIR)"

TESTS = \
	vtc/vmod_ja4.vtc \
	vtc/unload.vtc

# Documentation

EXTRA_DIST = \
	etc/example.com.pem

dist_doc_DATA = \
	vmod_ja4.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_ja4.3
