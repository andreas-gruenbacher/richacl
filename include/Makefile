#
# Copyright (c) 2008 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

HFILES = richacl.h richacl-internal.h richacl_xattr.h string_buffer.h
LSRCFILES = builddefs.in buildmacros buildrules config.h.in
LDIRT = sys

default: sys

sys:
	$(LN_S) . $@

include $(BUILDRULES)

install-dev: default
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)/sys
	$(INSTALL) -m 644 richacl.h $(PKG_INC_DIR)/sys/richacl.h

install install-lib:
