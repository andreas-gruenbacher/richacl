#
# Copyright (c) 2000, 2002 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

LTCOMMAND = richacl
CFILES = richacl.c user_group.c
HFILES = user_group.h

LLDLIBS = $(LIBRICHACL) $(LIBATTR)
LTDEPENDENCIES = $(LIBRICHACL)

default: $(LTCOMMAND)

include $(BUILDRULES)

install: default
	$(INSTALL) -m 755 -d $(PKG_BIN_DIR)
	$(LTINSTALL) -m 755 $(LTCOMMAND) $(PKG_BIN_DIR)
install-dev install-lib:
