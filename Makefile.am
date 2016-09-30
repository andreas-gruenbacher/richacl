ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	build-aux/git-version-gen \
	$(top_srcdir)/.version \
	exports \
	README \
	doc/COPYING \
	doc/COPYING-GPLv2 \
	doc/COPYING-LGPLv2 \
	INSTALL

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

AM_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

if NEED_UAPI
AM_CPPFLAGS += \
	-I$(top_srcdir)/include/uapi
endif

pkgconfdir = $(libdir)/pkgconfig
sysincludedir = $(includedir)/sys

pkgconf_DATA =
sysinclude_HEADERS =
bin_PROGRAMS =
lib_LTLIBRARIES =
noinst_HEADERS =
check_PROGRAMS =
dist_man_MANS =

include include/Makemodule.am
include lib/Makemodule.am
include src/Makemodule.am
include man/Makemodule.am
include tests/Makemodule.am
