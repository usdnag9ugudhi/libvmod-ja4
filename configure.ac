AC_PREREQ([2.69])
AC_INIT([libvmod-ja4], [1.0])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.12 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])

AC_ARG_VAR([RST2MAN], [the program to build manuals from reStructuredText])
AC_CHECK_PROGS([RST2MAN], [rst2man rst2man.py])

VARNISH_PREREQ([7.5.0])
VARNISH_VMODS([ja4])

# OpenSSL (libssl for Client Hello APIs, libcrypto for SHA-256)
AC_CHECK_HEADER([openssl/ssl.h], [], [AC_MSG_ERROR([openssl/ssl.h not found - install libssl-dev or openssl-devel])])
AC_CHECK_HEADER([openssl/evp.h], [], [AC_MSG_ERROR([openssl/evp.h not found])])
AC_CHECK_LIB([ssl], [SSL_new], [LIBSSL_LIBS="-lssl -lcrypto"], [AC_MSG_ERROR([libssl not found])])
AC_CHECK_LIB([crypto], [EVP_MD_CTX_new], [], [AC_MSG_ERROR([libcrypto not found])])
AC_SUBST([LIBSSL_LIBS])

AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	libvmod-ja4.spec
])

AC_OUTPUT

AS_ECHO("
	==== $PACKAGE_STRING ====

	varnish:      $VARNISH_VERSION
	prefix:       $prefix
	vmoddir:      $vmoddir
	vcldir:       $vcldir
	pkgvcldir:    $pkgvcldir

	compiler:     $CC
	cflags:       $CFLAGS
	ldflags:      $LDFLAGS
")
