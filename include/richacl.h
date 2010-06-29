/*
  Copyright (C) 2006, 2009, 2010  Novell, Inc.
  Written by Andreas Gruenbacher <agruen@suse.de>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __RICHACL_H
#define __RICHACL_H

#include <sys/types.h>
#include <string.h>

/* a_flags values */
#define ACL4_AUTO_INHERIT		0x01
#define ACL4_PROTECTED			0x02
#define ACL4_DEFAULTED			0x04
#define ACL4_POSIX_MAPPED		0x10

#define ACL4_VALID_FLAGS (	\
	ACL4_AUTO_INHERIT |	\
	ACL4_PROTECTED |	\
	ACL4_DEFAULTED |	\
	ACL4_POSIX_MAPPED)

/* e_type values */
#define ACE4_ACCESS_ALLOWED_ACE_TYPE    0x0000
#define ACE4_ACCESS_DENIED_ACE_TYPE     0x0001

/* e_flags bitflags */
#define ACE4_FILE_INHERIT_ACE		0x0001
#define ACE4_DIRECTORY_INHERIT_ACE	0x0002
#define ACE4_NO_PROPAGATE_INHERIT_ACE	0x0004
#define ACE4_INHERIT_ONLY_ACE		0x0008
#define ACE4_IDENTIFIER_GROUP		0x0040
#define ACE4_INHERITED_ACE		0x0080

#define ACE4_VALID_FLAGS (			\
	ACE4_FILE_INHERIT_ACE |			\
	ACE4_DIRECTORY_INHERIT_ACE |		\
	ACE4_NO_PROPAGATE_INHERIT_ACE |		\
	ACE4_INHERIT_ONLY_ACE |			\
	ACE4_IDENTIFIER_GROUP |			\
	ACE4_INHERITED_ACE )

/* e_mask bitflags */
#define ACE4_READ_DATA			0x00000001
#define ACE4_LIST_DIRECTORY		0x00000001
#define ACE4_WRITE_DATA			0x00000002
#define ACE4_ADD_FILE			0x00000002
#define ACE4_APPEND_DATA		0x00000004
#define ACE4_ADD_SUBDIRECTORY		0x00000004
#define ACE4_READ_NAMED_ATTRS		0x00000008
#define ACE4_WRITE_NAMED_ATTRS		0x00000010
#define ACE4_EXECUTE			0x00000020
#define ACE4_DELETE_CHILD		0x00000040
#define ACE4_READ_ATTRIBUTES		0x00000080
#define ACE4_WRITE_ATTRIBUTES		0x00000100
#define ACE4_WRITE_RETENTION		0x00000200
#define ACE4_WRITE_RETENTION_HOLD	0x00000400
#define ACE4_DELETE			0x00010000
#define ACE4_READ_ACL			0x00020000
#define ACE4_WRITE_ACL			0x00040000
#define ACE4_WRITE_OWNER		0x00080000
#define ACE4_SYNCHRONIZE		0x00100000

/* Valid ACE4_* flags for directories and non-directories */
#define ACE4_VALID_MASK (				\
	ACE4_READ_DATA | ACE4_LIST_DIRECTORY |		\
	ACE4_WRITE_DATA | ACE4_ADD_FILE |		\
	ACE4_APPEND_DATA | ACE4_ADD_SUBDIRECTORY |	\
	ACE4_READ_NAMED_ATTRS |				\
	ACE4_WRITE_NAMED_ATTRS |			\
	ACE4_EXECUTE |					\
	ACE4_DELETE_CHILD |				\
	ACE4_READ_ATTRIBUTES |				\
	ACE4_WRITE_ATTRIBUTES |				\
	ACE4_WRITE_RETENTION |				\
	ACE4_WRITE_RETENTION_HOLD |			\
	ACE4_DELETE |					\
	ACE4_READ_ACL |					\
	ACE4_WRITE_ACL |				\
	ACE4_WRITE_OWNER |				\
	ACE4_SYNCHRONIZE)

struct richace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	union {
		id_t		e_id;
		const char	*e_who;
	} u;
};

struct richacl {
	unsigned char	a_flags;
	unsigned short	a_count;
	unsigned int	a_owner_mask;
	unsigned int	a_group_mask;
	unsigned int	a_other_mask;
	struct richace  a_entries[0];
};

#define richacl_for_each_entry(_ace, _acl) \
	for ((_ace) = (_acl)->a_entries; \
	     (_ace) != (_acl)->a_entries + (_acl)->a_count; \
	     (_ace)++)

#define richacl_for_each_entry_reverse(_ace, _acl) \
	for ((_ace) = (_acl)->a_entries + (_acl)->a_count - 1; \
	     (_ace) != (_acl)->a_entries - 1; \
	     (_ace)--)

/* richacl_to_text flags */
#define RICHACL_TEXT_LONG		1
#define RICHACL_TEXT_FILE_CONTEXT	2
#define RICHACL_TEXT_DIRECTORY_CONTEXT	4
#define RICHACL_TEXT_SHOW_MASKS		8
#define RICHACL_TEXT_SIMPLIFY		16
#define RICHACL_TEXT_ALIGN		32
#define RICHACL_TEXT_NUMERIC_IDS	64

/* richacl_from_text flags */
#define RICHACL_TEXT_OWNER_MASK		1
#define RICHACL_TEXT_GROUP_MASK		2
#define RICHACL_TEXT_OTHER_MASK		4
#define RICHACL_TEXT_FLAGS		8

extern int richace_is_owner(const struct richace *);
extern int richace_is_group(const struct richace *);
extern int richace_is_everyone(const struct richace *);
extern int richace_is_unix_id(const struct richace *);

static inline int richace_is_allow(const struct richace *ace)
{
	return ace->e_type == ACE4_ACCESS_ALLOWED_ACE_TYPE;
}

static inline int richace_is_deny(const struct richace *ace)
{
	return ace->e_type == ACE4_ACCESS_DENIED_ACE_TYPE;
}

static inline int richace_is_inheritable(const struct richace *ace)
{
	return ace->e_flags & (ACE4_FILE_INHERIT_ACE |
			       ACE4_DIRECTORY_INHERIT_ACE);
}

static inline int richace_is_inherit_only(const struct richace *ace)
{
	return ace->e_flags & ACE4_INHERIT_ONLY_ACE;
}

static inline int richacl_is_auto_inherit(const struct richacl *acl)
{
	return acl->a_flags & ACL4_AUTO_INHERIT;
}

extern const char *richace_get_who(const struct richace *);

extern int richace_set_who(struct richace *, const char *);
extern void richace_set_uid(struct richace *, uid_t);
extern void richace_set_gid(struct richace *, gid_t);
extern int richace_is_same_identifier(const struct richace *,
				      const struct richace *);
extern void richace_copy(struct richace *, const struct richace *);

extern struct richacl *richacl_get_file(const char *);
extern struct richacl *richacl_get_fd(int);
extern int richacl_set_file(const char *, const struct richacl *);
extern int richacl_set_fd(int, const struct richacl *);

extern char *richacl_to_text(const struct richacl *, int);
extern struct richacl *richacl_from_text(const char *, int *,
					 void (*)(const char *, ...));

extern struct richacl *richacl_alloc(size_t);
extern struct richacl *richacl_clone(const struct richacl *);
extern void richacl_free(struct richacl *);

extern int richacl_apply_masks(struct richacl **);
extern void richacl_compute_max_masks(struct richacl *);
extern struct richacl *richacl_from_mode(mode_t);
extern int richacl_masks_to_mode(const struct richacl *);
extern struct richacl *richacl_inherit(const struct richacl *, int isdir);
extern int richacl_equiv_mode(const struct richacl *, mode_t *);
extern int richacl_compare(const struct richacl *, const struct richacl *);

struct stat;
extern int richacl_access(const char *, const struct stat *, uid_t,
			  const gid_t *, int);
extern char *richacl_mask_to_text(unsigned int, int);

extern struct richacl *richacl_auto_inherit(const struct richacl *,
					    const struct richacl *);

#endif  /* __RICHACL_H */
