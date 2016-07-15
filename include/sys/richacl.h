/*
  Copyright (C) 2006, 2009, 2010  Novell, Inc.
  Copyright (C) 2015  Red Hat, Inc.
  Written by Andreas Gruenbacher <agruenba@redhat.com>

  The richacl library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  The richacl library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef __RICHACL_H
#define __RICHACL_H

#include <sys/types.h>
#include <stdbool.h>

#include <linux/richacl.h>

struct richace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	union {
		id_t		e_id;
		char *		e_who;
	};
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
extern bool richace_is_unix_user(const struct richace *);
extern bool richace_is_unix_group(const struct richace *);

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

extern void richace_set_uid(struct richace *, uid_t);
extern void richace_set_gid(struct richace *, gid_t);
extern int richace_set_special_who(struct richace *, const char *);
extern int richace_set_unmapped_who(struct richace *, const char *, unsigned int);
extern bool richace_is_same_identifier(const struct richace *,
				       const struct richace *);
extern int richace_copy(struct richace *, const struct richace *);

extern struct richacl *richacl_get_file(const char *);
extern struct richacl *richacl_get_fd(int);
extern int richacl_set_file(const char *, const struct richacl *);
extern int richacl_set_fd(int, const struct richacl *);

extern char *richacl_to_text(const struct richacl *, int);
extern struct richacl *richacl_from_text(const char *, int *,
					 void (*)(const char *, ...));

extern struct richacl *richacl_alloc(unsigned int);
extern struct richacl *richacl_clone(const struct richacl *);
extern void richacl_free(struct richacl *);

extern int richacl_apply_masks(struct richacl **, uid_t);
extern void richacl_compute_max_masks(struct richacl *);
extern void richacl_chmod(struct richacl *, mode_t);
extern struct richacl *richacl_from_mode(mode_t);
extern int richacl_masks_to_mode(const struct richacl *);
extern struct richacl *richacl_inherit(const struct richacl *, int isdir);
extern int richacl_equiv_mode(const struct richacl *, mode_t *);
extern int richacl_compare(const struct richacl *, const struct richacl *);

struct stat;
extern int richacl_access(const char *, const struct stat *, uid_t,
			  const gid_t *, int);
extern bool richacl_permission(struct richacl *, uid_t, gid_t, uid_t, const gid_t *,
			       int, unsigned int);

extern char *richacl_mask_to_text(unsigned int, int);

extern struct richacl *richacl_auto_inherit(const struct richacl *, const struct richacl *);
extern struct richacl *richacl_inherit_inode(const struct richacl *, mode_t *,
					     mode_t (*)(void *), void *);

extern size_t richacl_xattr_size(const struct richacl *acl);
extern struct richacl *richacl_from_xattr(const void *value, size_t size);
extern void richacl_to_xattr(const struct richacl *acl, void *buffer);
extern int richacl_valid(struct richacl *);

#endif  /* __RICHACL_H */
