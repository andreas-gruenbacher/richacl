#
# Copyright (c) 2008 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

HFILES = nfs4acl.h nfs4acl-internal.h nfs4acl_xattr.h string_buffer.h
LSRCFILES = builddefs.in buildmacros buildrules config.h.in
LDIRT = sys

sys:
	$(LN_S) . $@

default: sys

include $(BUILDRULES)

install-dev: default
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)/sys
	$(INSTALL) -m 644 nfs4acl.h $(PKG_INC_DIR)/sys/nfs4acl.h

install install-lib:
