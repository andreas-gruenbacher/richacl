AC_INIT([richacl],
	m4_esyscmd([build-aux/git-version-gen .tarball-version]),
	[agruenba@redhat.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([include/config.h])
#AC_PREFIX_DEFAULT(/usr)

AM_INIT_AUTOMAKE([-Wall foreign 1.11 dist-xz subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_FUNC_GCC_VISIBILITY

AM_PROG_AR
LT_INIT

AC_CHECK_HEADER([sys/xattr.h],,
  [AC_MSG_ERROR([cannot find header <sys/xattr.h>])])

#AM_GNU_GETTEXT_VERSION([0.18.2])
#AM_GNU_GETTEXT([external])

#AC_ARG_ENABLE([debug],
#        [AS_HELP_STRING([--enable-debug], [Enable extra debugging])])
#AS_IF([test "x$enable_debug" = "xyes"],
#        [CPPFLAGS="$CPPFLAGS -DDEBUG"],
#        [CPPFLAGS="$CPPFLAGS -DNDEBUG"])

dnl Automatically increment the revision for every release.
LT_REVISION=$(echo "${PACKAGE_VERSION}" | sed -e 's:\..*::' -e 's:-dirty$::')
AC_SUBST(LT_REVISION)

AC_CONFIG_FILES([
	lib/librichacl.pc
	Makefile
])
AC_OUTPUT
