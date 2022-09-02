AC_PREREQ([2.68])
AC_INIT([security], [0.1])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.12 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_ARG_WITH([rst2man],
    AS_HELP_STRING(
        [--with-rst2man=PATH],
        [Location of rst2man (auto)]),
    [RST2MAN="$withval"],
    [AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [])])

PKG_CHECK_VAR([VARNISHAPI_LIBDIR], [varnishapi], [libdir])
AC_SUBST([VARNISH_LIBRARY_PATH],
    [$VARNISHAPI_LIBDIR:$VARNISHAPI_LIBDIR/varnish])

dnl Check the ModSecurity libraries (modsecurity)

PKG_CHECK_VAR([MODSECURITY_LIBDIR], [modsecurity], [libdir])
PKG_CHECK_VAR([MODSECURITY_CFLAGS], [modsecurity], [cflags])
AC_SUBST([MODSECURITY_LIBRARY_PATH],
    [$MODSECURITY_LIBDIR:$MODSECURITY_LIBDIR/modsecurity])
AC_SUBST([MODSECURITY_CFLAGS], [$MODSECURITY_CFLAGS])

AC_CHECK_LIB([modsecurity], [msc_init], [
        AC_DEFINE([HAVE_MODSECURITYLIB], [1],
                [Define to 1 if you have the `libmodsecurity' library ( ).])], [
        AC_MSG_ERROR([ModSecurity libraries not found!])

AC_CHECK_HEADERS([modsecurity/modsecurity.h], [], [
        AC_MSG_ERROR([ModSecurity headers not found...])])
])

VARNISH_PREREQ([7.0.0])
VARNISH_VMODS([sec])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    security.spec
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
