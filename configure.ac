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

# https://www.gnu.org/software/autoconf-archive/ax_prog_apache.html#ax_prog_apache
AC_DEFUN([FIND_LIBMOD],[
AC_MSG_NOTICE(looking for libmodsecurity)
# Check if the user provided --with-libmodsecurity
AC_ARG_WITH(libmodsecurity,
            [AS_HELP_STRING([[--with-libmodsecurity=FILE]],
                            [FILE is the path to libmodsecurity install dir; defaults to "/usr/local/modsecurity/".])],
[
  if test "$withval" = "yes"; then
    AC_SUBST(CPPFLAGS, "$CPPFLAGS -I/usr/local/modsecurity/include/ -L/usr/local/modsecurity/lib/")
    V3INCLUDE="/usr/local/modsecurity/include/"
    V3LIB="/usr/local/modsecurity/lib/"
  else
    AC_SUBST(CPPFLAGS, "$CPPFLAGS -I${withval}/include/ -L${withval}/lib/")
    V3INCLUDE="${withval}/include/"
    V3LIB="${withval}/lib/"
  fi
])

dnl Check the ModSecurity libraries (modsecurity)

AC_CHECK_LIB([modsecurity], [msc_init], [
        AC_DEFINE([HAVE_MODSECURITYLIB], [1],
                [Define to 1 if you have the `libmodsecurity' library ( ).])], [
        AC_MSG_ERROR([ModSecurity libraries not found!])])

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
