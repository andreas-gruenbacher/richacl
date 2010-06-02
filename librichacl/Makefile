#
# Copyright (c) 2000-2002 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..

LTLDFLAGS += -Wl,--version-script,$(TOPDIR)/exports
include $(TOPDIR)/include/builddefs

LTLIBRARY = librichacl.la
LTLIBS = -lattr $(LIBMISC)
LTDEPENDENCIES = $(LIBMISC)
LT_CURRENT = 2
LT_REVISION = 0
LT_AGE = 1

LCFLAGS =

HFILES = byteorder.h
CFILES = richacl.c  richacl_compat.c  string_buffer.c

default: $(LTLIBRARY)

include $(BUILDRULES)

install:

install-dev: default
	$(INSTALL_LTLIB_DEV)

install-lib: default
	$(INSTALL_LTLIB)
