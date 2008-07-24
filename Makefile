NAME := nfs4acl
VERSION := 0.9

INCLUDE_SOURCES := include/nfs4acl.h include/nfs4acl_xattr.h include/nfs4acl-internal.h include/string_buffer.h
SRC_SOURCES := src/nfs4acl.c
LIB_SOURCES := lib/nfs4acl.c lib/nfs4acl_compat.c lib/string_buffer.c
PATCHES := patches.sles10-sp2/series $(patsubst %,patches.sles10-sp2/%,$(shell grep -v \\\# patches.sles10-sp2/series))
PATCHES += patches.git/series $(patsubst %,patches.git/%,$(shell grep -v \\\# patches.git/series))
TESTS := test/run $(wildcard test/*.test)
SOURCES := Makefile $(INCLUDE_SOURCES) $(SRC_SOURCES) $(LIB_SOURCES) $(PATCHES) $(TESTS)

CPPFLAGS := -Iinclude
CFLAGS := -g -Wall -DVERSION=\"$(VERSION)\"
LDFLAGS := -g

all: src/nfs4acl

src/nfs4acl : src/nfs4acl.o lib/libnfs4acl.a
	$(CC) $(LDFLAGS) -o $@ $+

lib/libnfs4acl.a : lib/nfs4acl.o lib/string_buffer.o lib/nfs4acl_compat.o
	$(RM) -f $@
	$(AR) r $@ $+

prefix=		/usr/local
exec_prefix=	$(prefix)
includedir=		$(prefix)/include
libdir=		$(exec_prefix)/lib
sbindir=	$(exec_prefix)/sbin
pkgdatadir=	$(prefix)/share/$(NAME)
INSTALL=	install -c

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(includedir)/$(NAME)
	for file in $(INCLUDE_SOURCES) ; do $(INSTALL) -m 644 $$file $(DESTDIR)$(includedir)/$(NAME) ; done
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(INSTALL) -m 644 lib/libnfs4acl.a $(DESTDIR)$(libdir)
	$(INSTALL) -d -m 755 $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 src/nfs4acl $(DESTDIR)$(sbindir)
	$(INSTALL) -d -m 755 $(DESTDIR)$(pkgdatadir)/test
	for file in $(TESTS) ; do $(INSTALL) -m 644 $$file $(DESTDIR)$(pkgdatadir)/test ; done
	chmod 755 $(DESTDIR)$(pkgdatadir)/test/run

dist:
	rm -f $(NAME)-$(VERSION)
	ln -s . $(NAME)-$(VERSION)
	tar cfz $(NAME)-$(VERSION).tar.gz ${SOURCES:%=$(NAME)-$(VERSION)/%}
	rm -f $(NAME)-$(VERSION)

clean:
	rm -f src/nfs4acl.o lib/libnfs4acl.a lib/nfs4acl.o lib/string_buffer.o lib/nfs4acl_compat.o
