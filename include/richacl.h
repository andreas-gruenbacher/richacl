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
#include <stdbool.h>

/* a_flags values */
#define RICHACL_AUTO_INHERIT		0x01
#define RICHACL_PROTECTED			0x02
#define RICHACL_DEFAULTED			0x04
/* richacl specific acl flag */
#define RICHACL_MASKED			0x80


#define RICHACL_VALID_FLAGS (	\
	RICHACL_AUTO_INHERIT |	\
	RICHACL_PROTECTED |	\
	RICHACL_DEFAULTED |	\
	RICHACL_MASKED)

/* e_type values */
#define RICHACE_ACCESS_ALLOWED_ACE_TYPE    0x0000
#define RICHACE_ACCESS_DENIED_ACE_TYPE     0x0001

/* e_flags bitflags */
#define RICHACE_FILE_INHERIT_ACE		0x0001
#define RICHACE_DIRECTORY_INHERIT_ACE	0x0002
#define RICHACE_NO_PROPAGATE_INHERIT_ACE	0x0004
#define RICHACE_INHERIT_ONLY_ACE		0x0008
#define RICHACE_IDENTIFIER_GROUP		0x0040
#define RICHACE_INHERITED_ACE		0x0080
/* richacl specific acl entry flag */
#define RICHACE_SPECIAL_WHO		0x4000

#define RICHACE_VALID_FLAGS (			\
	RICHACE_FILE_INHERIT_ACE |			\
	RICHACE_DIRECTORY_INHERIT_ACE |		\
	RICHACE_NO_PROPAGATE_INHERIT_ACE |		\
	RICHACE_INHERIT_ONLY_ACE |			\
	RICHACE_IDENTIFIER_GROUP |			\
	RICHACE_INHERITED_ACE  |			\
	RICHACE_SPECIAL_WHO)

/* e_mask bitflags */
#define RICHACE_READ_DATA			0x00000001
#define RICHACE_LIST_DIRECTORY		0x00000001
#define RICHACE_WRITE_DATA			0x00000002
#define RICHACE_ADD_FILE			0x00000002
#define RICHACE_APPEND_DATA		0x00000004
#define RICHACE_ADD_SUBDIRECTORY		0x00000004
#define RICHACE_READ_NAMED_ATTRS		0x00000008
#define RICHACE_WRITE_NAMED_ATTRS		0x00000010
#define RICHACE_EXECUTE			0x00000020
#define RICHACE_DELETE_CHILD		0x00000040
#define RICHACE_READ_ATTRIBUTES		0x00000080
#define RICHACE_WRITE_ATTRIBUTES		0x00000100
#define RICHACE_WRITE_RETENTION		0x00000200
#define RICHACE_WRITE_RETENTION_HOLD	0x00000400
#define RICHACE_DELETE			0x00010000
#define RICHACE_READ_ACL			0x00020000
#define RICHACE_WRITE_ACL			0x00040000
#define RICHACE_WRITE_OWNER		0x00080000
#define RICHACE_SYNCHRONIZE		0x00100000

/* Valid RICHACE_* flags for directories and non-directories */
#define RICHACE_VALID_MASK (				\
	RICHACE_READ_DATA | RICHACE_LIST_DIRECTORY |		\
	RICHACE_WRITE_DATA | RICHACE_ADD_FILE |		\
	RICHACE_APPEND_DATA | RICHACE_ADD_SUBDIRECTORY |	\
	RICHACE_READ_NAMED_ATTRS |				\
	RICHACE_WRITE_NAMED_ATTRS |			\
	RICHACE_EXECUTE |					\
	RICHACE_DELETE_CHILD |				\
	RICHACE_READ_ATTRIBUTES |				\
	RICHACE_WRITE_ATTRIBUTES |				\
	RICHACE_WRITE_RETENTION |				\
	RICHACE_WRITE_RETENTION_HOLD |			\
	RICHACE_DELETE |					\
	RICHACE_READ_ACL |					\
	RICHACE_WRITE_ACL |				\
	RICHACE_WRITE_OWNER |				\
	RICHACE_SYNCHRONIZE)

/*
 * The POSIX permissions are supersets of the following mask flags.
 */
#define RICHACE_POSIX_MODE_READ ( \
	RICHACE_READ_DATA | RICHACE_LIST_DIRECTORY )
#define RICHACE_POSIX_MODE_WRITE ( \
	RICHACE_WRITE_DATA | RICHACE_ADD_FILE | \
	RICHACE_APPEND_DATA | RICHACE_ADD_SUBDIRECTORY | \
	RICHACE_DELETE_CHILD )
#define RICHACE_POSIX_MODE_EXEC ( \
	RICHACE_EXECUTE)
#define RICHACE_POSIX_MODE_ALL ( \
	RICHACE_POSIX_MODE_READ | \
	RICHACE_POSIX_MODE_WRITE | \
	RICHACE_POSIX_MODE_EXEC)

/*
 * The RICHACE_READ_ATTRIBUTES and RICHACE_READ_ACL flags are always granted
 * in POSIX. The RICHACE_SYNCHRONIZE flag has no meaning under POSIX.
 */
#define RICHACE_POSIX_ALWAYS_ALLOWED ( \
	RICHACE_SYNCHRONIZE | \
	RICHACE_READ_ATTRIBUTES | \
	RICHACE_READ_ACL )

/* The owner is implicitly granted these permissions under POSIX. */
#define RICHACE_POSIX_OWNER_ALLOWED ( \
	RICHACE_WRITE_ATTRIBUTES | \
	RICHACE_WRITE_OWNER | \
	RICHACE_WRITE_ACL)

/* Special e_id values for (e_flags & RICHACE_SPECIAL_WHO) */
#define RICHACE_OWNER_SPECIAL_ID	0
#define RICHACE_GROUP_SPECIAL_ID	1
#define RICHACE_EVERYONE_SPECIAL_ID	2

struct richace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	id_t		e_id;
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

extern bool richace_is_owner(const struct richace *);
extern bool richace_is_group(const struct richace *);
extern bool richace_is_everyone(const struct richace *);
extern bool richace_is_unix_id(const struct richace *);

static inline bool richace_is_allow(const struct richace *ace)
{
	return ace->e_type == RICHACE_ACCESS_ALLOWED_ACE_TYPE;
}

static inline bool richace_is_deny(const struct richace *ace)
{
	return ace->e_type == RICHACE_ACCESS_DENIED_ACE_TYPE;
}

static inline bool richace_is_inheritable(const struct richace *ace)
{
	return ace->e_flags & (RICHACE_FILE_INHERIT_ACE |
			       RICHACE_DIRECTORY_INHERIT_ACE);
}

static inline bool richace_is_inherit_only(const struct richace *ace)
{
	return ace->e_flags & RICHACE_INHERIT_ONLY_ACE;
}

static inline bool richacl_is_auto_inherit(const struct richacl *acl)
{
	return acl->a_flags & RICHACL_AUTO_INHERIT;
}

static inline int richace_is_inherited(const struct richace *ace)
{
	return ace->e_flags & RICHACE_INHERITED_ACE;
}

extern int richace_set_who(struct richace *, const char *);
extern void richace_set_uid(struct richace *, uid_t);
extern void richace_set_gid(struct richace *, gid_t);
extern bool richace_is_same_identifier(const struct richace *,
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
bool richacl_permission(struct richacl *, uid_t, gid_t, uid_t, const gid_t *,
			int, unsigned int);

extern char *richacl_mask_to_text(unsigned int, int);

extern struct richacl *richacl_auto_inherit(const struct richacl *,
					    const struct richacl *);

#endif  /* __RICHACL_H */
