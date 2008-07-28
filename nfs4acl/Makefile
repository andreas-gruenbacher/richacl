#
# Copyright (c) 2000, 2002 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

LTCOMMAND = nfs4acl
CFILES = nfs4acl.c
HFILES =

LLDLIBS = $(LIBNFS4ACL) $(LIBATTR)
LTDEPENDENCIES = $(LIBNFS4ACL)

default: $(LTCOMMAND)

include $(BUILDRULES)

install: default
	$(INSTALL) -m 755 -d $(PKG_BIN_DIR)
	$(LTINSTALL) -m 755 $(LTCOMMAND) $(PKG_BIN_DIR)
install-dev install-lib:
