AM_CFLAGS = $(VARNISHAPI_CFLAGS)

# Modules

vmod_LTLIBRARIES = \
	libvmod_ja4.la

libvmod_ja4_la_LDFLAGS = $(VMOD_LDFLAGS) $(LIBSSL_LIBS)

libvmod_ja4_la_SOURCES = \
	vmod_ja4.c

nodist_libvmod_ja4_la_SOURCES = \
	vcc_ja4_if.c \
	vcc_ja4_if.h

@BUILD_VMOD_JA4@

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VARNISHAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VARNISHAPI_VMODDIR)"

TESTS = \
	vtc/vmod_ja4.vtc

# Documentation

EXTRA_DIST = \
	etc/example.com.pem

dist_doc_DATA = \
	vmod_ja4.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_ja4.3
