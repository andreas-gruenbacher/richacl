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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "richacl.h"
#include "richacl-internal.h"

const char *richace_owner_who	 = "OWNER@";
const char *richace_group_who	 = "GROUP@";
const char *richace_everyone_who = "EVERYONE@";

const char *richace_get_who(const struct richace *ace)
{
	if (!(ace->e_flags & ACE4_SPECIAL_WHO))
		return NULL;
	return ace->u.e_who;
}

int richace_is_same_identifier(const struct richace *a, const struct richace *b)
{
#define WHO_FLAGS (ACE4_SPECIAL_WHO | ACE4_IDENTIFIER_GROUP)
	if ((a->e_flags & WHO_FLAGS) != (b->e_flags & WHO_FLAGS))
		return 0;
	if (a->e_flags & ACE4_SPECIAL_WHO)
		return a->u.e_who == b->u.e_who;
	else
		return a->u.e_id == b->u.e_id;
#undef WHO_FLAGS
}

int richace_is_owner(const struct richace *ace)
{
	return (ace->e_flags & ACE4_SPECIAL_WHO) &&
		ace->u.e_who == richace_owner_who;
}

int richace_is_group(const struct richace *ace)
{
	return (ace->e_flags & ACE4_SPECIAL_WHO) &&
		ace->u.e_who == richace_group_who;
}

int richace_is_everyone(const struct richace *ace)
{
	return (ace->e_flags & ACE4_SPECIAL_WHO) &&
		ace->u.e_who == richace_everyone_who;
}

struct richacl *richacl_alloc(size_t count)
{
	size_t size = sizeof(struct richacl) + count * sizeof(struct richace);
	struct richacl *acl = malloc(size);

	if (acl) {
		memset(acl, 0, size);
		acl->a_count = count;
	}
	return acl;
}

struct richacl *richacl_clone(const struct richacl *acl)
{
	size_t size;
	struct richacl *acl2;

	if (!acl)
		return NULL;
	size = sizeof(struct richacl) + acl->a_count * sizeof(struct richace);
	acl2 = malloc(size);
	if (acl2)
		memcpy(acl2, acl, size);
	return acl2;
}

void richacl_free(struct richacl *acl)
{
	free(acl);
}

/**
 * richacl_allowed_to_who  -  mask flags allowed to a specific who value
 *
 * Computes the mask values allowed to a specific who value, taking
 * EVERYONE@ entries into account.
 */
static unsigned int richacl_allowed_to_who(struct richacl *acl,
					   struct richace *who)
{
	struct richace *ace;
	unsigned int allowed = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_same_identifier(ace, who) ||
		    richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				allowed |= ace->e_mask;
			else if (richace_is_deny(ace))
				allowed &= ~ace->e_mask;
		}
	}
	return allowed;
}

/**
 * richacl_group_class_allowed  -  maximum permissions the group class is allowed
 *
 * See richacl_compute_max_masks().
 */
static unsigned int richacl_group_class_allowed(struct richacl *acl)
{
	struct richace *ace;
	unsigned int everyone_allowed = 0, group_class_allowed = 0;
	int had_group_ace = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace) ||
		    richace_is_owner(ace))
			continue;

		if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				everyone_allowed |= ace->e_mask;
			else if (richace_is_deny(ace))
				everyone_allowed &= ~ace->e_mask;
		} else {
			group_class_allowed |=
				richacl_allowed_to_who(acl, ace);

			if (richace_is_group(ace))
				had_group_ace = 1;
		}
	}
	if (!had_group_ace)
		group_class_allowed |= everyone_allowed;
	return group_class_allowed;
}

/**
 * richacl_compute_max_masks  -  compute upper bound masks
 *
 * Computes upper bound owner, group, and other masks so that none of
 * the mask flags allowed by the acl are disabled (for any choice of the
 * file owner or group membership).
 */
void richacl_compute_max_masks(struct richacl *acl)
{
	unsigned int gmask = ~0;
	struct richace *ace;

	/*
	 * @gmask contains all permissions which the group class is ever
	 * allowed.  We use it to avoid adding permissions to the group mask
	 * from everyone@ allow aces which the group class is always denied
	 * through other aces.  For example, the following acl would otherwise
	 * result in a group mask or rw:
	 *
	 * 	group@:w::deny
	 * 	everyone@:rw::allow
	 *
	 * Avoid computing @gmask for acls which do not include any group class
	 * deny aces: in such acls, the group class is never denied any
	 * permissions from everyone@ allow aces.
	 */

restart:
	acl->a_owner_mask = 0;
	acl->a_group_mask = 0;
	acl->a_other_mask = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;

		if (richace_is_owner(ace)) {
			if (richace_is_allow(ace))
				acl->a_owner_mask |= ace->e_mask;
			else if (richace_is_deny(ace))
				acl->a_owner_mask &= ~ace->e_mask;
		} else if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace)) {
				acl->a_owner_mask |= ace->e_mask;
				acl->a_group_mask |= ace->e_mask & gmask;
				acl->a_other_mask |= ace->e_mask;
			} else if (richace_is_deny(ace)) {
				acl->a_owner_mask &= ~ace->e_mask;
				acl->a_group_mask &= ~ace->e_mask;
				acl->a_other_mask &= ~ace->e_mask;
			}
		} else {
			if (richace_is_allow(ace)) {
				acl->a_owner_mask |= ace->e_mask & gmask;
				acl->a_group_mask |= ace->e_mask & gmask;
			} else if (richace_is_deny(ace) && gmask == ~0) {
				gmask = richacl_group_class_allowed(acl);
				if (gmask != ~0)  /* should always be true */
					goto restart;
			}
		}
	}

	acl->a_flags &= ~ACL4_MASKED;
}

int richace_set_who(struct richace *ace, const char *who)
{
	if (!strcmp(who, richace_owner_who))
		who = richace_owner_who;
	else if (!strcmp(who, richace_group_who))
		who = richace_group_who;
	else if (!strcmp(who, richace_everyone_who))
		who = richace_everyone_who;
	else
		return -1;

	ace->u.e_who = who;
	ace->e_flags |= ACE4_SPECIAL_WHO;
	/*
	 * Also clear the ACE4_IDENTIFIER_GROUP flag for ACEs with a special
	 * who value: richace_is_same_identifier() relies on that.
	 */
	ace->e_flags &= ~ACE4_IDENTIFIER_GROUP;
	return 0;
}

void richace_set_uid(struct richace *ace, uid_t uid)
{
	ace->u.e_id = uid;
	ace->e_flags &= ~(ACE4_SPECIAL_WHO | ACE4_IDENTIFIER_GROUP);
}

void richace_set_gid(struct richace *ace, gid_t gid)
{
	ace->u.e_id = gid;
	ace->e_flags |= ACE4_IDENTIFIER_GROUP;
	ace->e_flags &= ~ACE4_SPECIAL_WHO;
}

void richace_copy(struct richace *dst, const struct richace *src)
{
	memcpy(dst, src, sizeof(struct richace));
}

/**
 * richacl_mode_to_mask  - compute a file mask from the lowest three mode bits
 *
 * See richacl_masks_to_mode().
 */
static unsigned int richacl_mode_to_mask(mode_t mode)
{
	unsigned int mask = ACE4_POSIX_ALWAYS_ALLOWED;

	if (mode & S_IROTH)
		mask |= ACE4_POSIX_MODE_READ;
	if (mode & S_IWOTH)
		mask |= ACE4_POSIX_MODE_WRITE;
	if (mode & S_IXOTH)
		mask |= ACE4_POSIX_MODE_EXEC;

	return mask;
}

/**
 * richacl_from_mode  -  create an acl which corresponds to @mode
 * @mode:       file mode including the file type
 */
struct richacl *richacl_from_mode(mode_t mode)
{
	struct richacl *acl;
	struct richace *ace;

	acl = richacl_alloc(1);
	if (!acl)
		return NULL;
	acl->a_flags = ACL4_MASKED;
	acl->a_owner_mask = richacl_mode_to_mask(mode >> 6);
	acl->a_group_mask = richacl_mode_to_mask(mode >> 3);
	acl->a_other_mask = richacl_mode_to_mask(mode);

	ace = acl->a_entries;
	ace->e_type = ACE4_ACCESS_ALLOWED_ACE_TYPE;
	ace->e_flags = ACE4_SPECIAL_WHO;
	ace->e_mask = ACE4_POSIX_MODE_ALL;
	/* ACE4_DELETE_CHILD is meaningless for non-directories. */
	if (!S_ISDIR(mode))
		ace->e_mask &= ~ACE4_DELETE_CHILD;
	ace->u.e_who = richace_everyone_who;

	return acl;
}

int richace_is_unix_id(const struct richace *ace)
{
	return !(ace->e_flags & ACE4_SPECIAL_WHO);
}

static int in_groups(gid_t group, gid_t groups[], int n_groups)
{
	int n;

	for (n = 0; n < n_groups; n++)
		if (group == groups[n])
			return 1;
	return 0;
}

int richacl_access(const char *file, const struct stat *st, uid_t user,
		   const gid_t *const_groups, int n_groups)
{
	const struct richacl *acl;
	struct stat local_st;
	const struct richace *ace;
	unsigned int file_mask, mask = ACE4_VALID_MASK, denied = 0;
	int in_owning_group;
	int in_owner_or_group_class;
	gid_t *groups = NULL;

	if (!st) {
		if (stat(file, &local_st) != 0)
			return -1;
		st = &local_st;
	}

	acl = richacl_get_file(file);
	if (!acl) {
		if (errno == ENODATA || errno == ENOTSUP || errno == ENOSYS) {
			acl = richacl_from_mode(st->st_mode);
			if (!acl)
				return -1;
		} else
			return -1;
	}

	if (n_groups < 0) {
		n_groups = getgroups(0, NULL);
		if (n_groups < 0)
			return -1;
		groups = malloc(sizeof(gid_t) * (n_groups + 1));
		if (!groups)
			return -1;
		groups[0] = getegid();
		if (getgroups(n_groups, groups + 1) < 0) {
			free(groups);
			return -1;
		}
	} else
		groups = (gid_t *)const_groups;  /* cast away const */

	in_owning_group = in_groups(st->st_gid, groups, n_groups);
	in_owner_or_group_class = in_owning_group;

	/*
	 * We don't need to know which class the process is in when the acl is
	 * not masked.
	 */
	if (!(acl->a_flags & ACL4_MASKED))
		in_owner_or_group_class = 1;

	/*
	 * A process is
	 *   - in the owner file class if it owns the file,
	 *   - in the group file class if it is in the file's owning group or
	 *     it matches any of the user or group entries, and
	 *   - in the other file class otherwise.
	 */

	richacl_for_each_entry(ace, acl) {
		unsigned int ace_mask = ace->e_mask;

		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_owner(ace)) {
			if (user != st->st_uid)
				continue;
			goto is_owner;
		} else if (richace_is_group(ace)) {
			if (!in_owning_group)
				continue;
		} else if (richace_is_unix_id(ace)) {
			if (ace->e_flags & ACE4_IDENTIFIER_GROUP) {
				if (!in_groups(ace->u.e_id, groups, n_groups))
					continue;
			} else {
				if (user != ace->u.e_id)
					continue;
			}
		} else
			goto is_everyone;

		/*
		 * Apply the group file mask to entries other than OWNER@ and
		 * EVERYONE@. This is not required for correct access checking
		 * but ensures that we grant the same permissions as the acl
		 * computed by richacl_apply_masks() would grant.
		 */
		if ((acl->a_flags & ACL4_MASKED) && richace_is_allow(ace))
			ace_mask &= acl->a_group_mask;

is_owner:
		/* The process is in the owner or group file class. */
		in_owner_or_group_class = 1;

is_everyone:
		/* Check which mask flags the ACE allows or denies. */
		if (richace_is_deny(ace))
			denied |= ace_mask & mask;
		mask &= ~ace_mask;
		if (!mask)
			break;
	}
	denied |= mask;

	/*
	 * Figure out which file mask applies.
	 */
	if (!(acl->a_flags & ACL4_MASKED))
		file_mask = ACE4_VALID_MASK;
	else if (user == st->st_uid) {
		file_mask = acl->a_owner_mask |
			    (ACE4_WRITE_ATTRIBUTES | ACE4_WRITE_OWNER | ACE4_WRITE_ACL);
		denied &= ~(ACE4_WRITE_ATTRIBUTES | ACE4_WRITE_OWNER | ACE4_WRITE_ACL);
	} else if (in_owner_or_group_class)
		file_mask = acl->a_group_mask;
	else
		file_mask = acl->a_other_mask;
	/* ACE4_DELETE_CHILD is meaningless for non-directories. */
	if (!S_ISDIR(st->st_mode))
		file_mask &= ~ACE4_DELETE_CHILD;

	if (groups != const_groups)
		free(groups);

	return ACE4_POSIX_ALWAYS_ALLOWED | (file_mask & ~denied);
}

/**
 * richacl_mask_to_mode  -  compute the file permission bits which correspond to @mask
 * @mask:	%ACE4_* permission mask
 *
 * See richacl_masks_to_mode().
 */
static int
richacl_mask_to_mode(unsigned int mask)
{
	int mode = 0;

	if (mask & ACE4_POSIX_MODE_READ)
		mode |= MAY_READ;
	if (mask & ACE4_POSIX_MODE_WRITE)
		mode |= MAY_WRITE;
	if (mask & ACE4_POSIX_MODE_EXEC)
		mode |= MAY_EXEC;

	return mode;
}

/**
 * richacl_masks_to_mode  -  compute the file permission bits from the file masks
 *
 * When the file permission bits of a file are set with chmod(), this specifies
 * the maximum permissions that processes will get.  All permissions beyond
 * that are removed from the file masks, and become ineffective.
 *
 * Conversely, when setting a richacl, we set the file permission bits to
 * indicate maximum permissions: for example, we set the Write permission when
 * a mask contains ACE4_APPEND_DATA even if it does not also contain
 * ACE4_WRITE_DATA.
 *
 * Permissions which are not in ACE4_POSIX_MODE_READ, ACE4_POSIX_MODE_WRITE, or
 * ACE4_POSIX_MODE_EXEC cannot be represented in the file permission bits.
 * Those permissions can still be effective, but only if the masks were set
 * explicitly (for example, by setting the richacl xattr), and not for new
 * files or after a chmod().
 */
int
richacl_masks_to_mode(const struct richacl *acl)
{
	return richacl_mask_to_mode(acl->a_owner_mask) << 6 |
	       richacl_mask_to_mode(acl->a_group_mask) << 3 |
	       richacl_mask_to_mode(acl->a_other_mask);
}

/**
 * richacl_inherit  -  compute the inheritable acl
 * @dir_acl:	acl of the containing direcory
 * @isdir:	inherit by a directory or non-directory?
 *
 * A directory can have acl entries which files and/or directories created
 * inside the directory will inherit.  This function computes the acl for such
 * a new file.  If there is no inheritable acl, it will return %NULL.
 */
struct richacl *
richacl_inherit(const struct richacl *dir_acl, int isdir)
{
	const struct richace *dir_ace;
	struct richacl *acl = NULL;
	struct richace *ace;
	int count = 0;

	if (isdir) {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!richace_is_inheritable(dir_ace))
				continue;
			count++;
		}
		if (!count)
			return NULL;
		acl = richacl_alloc(count);
		if (!acl)
			return NULL;
		ace = acl->a_entries;
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!richace_is_inheritable(dir_ace))
				continue;
			memcpy(ace, dir_ace, sizeof(struct richace));
			if (dir_ace->e_flags & ACE4_NO_PROPAGATE_INHERIT_ACE)
				richace_clear_inheritance_flags(ace);
			if ((dir_ace->e_flags & ACE4_FILE_INHERIT_ACE) &&
			    !(dir_ace->e_flags & ACE4_DIRECTORY_INHERIT_ACE))
				ace->e_flags |= ACE4_INHERIT_ONLY_ACE;
			ace++;
		}
	} else {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & ACE4_FILE_INHERIT_ACE))
				continue;
			count++;
		}
		if (!count)
			return NULL;
		acl = richacl_alloc(count);
		if (!acl)
			return NULL;
		ace = acl->a_entries;
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & ACE4_FILE_INHERIT_ACE))
				continue;
			memcpy(ace, dir_ace, sizeof(struct richace));
			richace_clear_inheritance_flags(ace);
			/*
			 * ACE4_DELETE_CHILD is meaningless for
			 * non-directories, so clear it.
			 */
			ace->e_mask &= ~ACE4_DELETE_CHILD;
			ace++;
		}
	}

	if (richacl_is_auto_inherit(dir_acl)) {
		acl->a_flags = ACL4_AUTO_INHERIT;
		richacl_for_each_entry(ace, acl)
			ace->e_flags |= ACE4_INHERITED_ACE;
	}

	return acl;
}

/**
 * richacl_equiv_mode  -  determine if @acl is equivalent to a file mode
 * @mode_p:	the file mode
 *
 * The file type in @mode_p must be set when calling richacl_equiv_mode().
 * Returns with 0 if @acl is equivalent to a file mode; in that case, the
 * file permission bits in @mode_p are set to the mode equivalent to @acl.
 */
int
richacl_equiv_mode(const struct richacl *acl, mode_t *mode_p)
{
	const struct richace *ace = acl->a_entries;
	unsigned int x = ~ACE4_POSIX_ALWAYS_ALLOWED;  /* mask flags we care about */
	mode_t mode;

	if (acl->a_count != 1 ||
	    acl->a_flags != ACL4_MASKED ||
	    !richace_is_everyone(ace) ||
	    !richace_is_allow(ace) ||
	    ace->e_flags & ~ACE4_SPECIAL_WHO)
		return -1;

	/* ACE4_DELETE_CHILD is meaningless for non-directories. */
	if (!S_ISDIR(*mode_p))
		x &= ~ACE4_DELETE_CHILD;

	if ((ace->e_mask & x) != (ACE4_POSIX_MODE_ALL & x))
		return -1;

	mode = richacl_masks_to_mode(acl);
	if ((acl->a_owner_mask & x) != (richacl_mode_to_mask(mode >> 6) & x) ||
	    (acl->a_group_mask & x) != (richacl_mode_to_mask(mode >> 3) & x) ||
	    (acl->a_other_mask & x) != (richacl_mode_to_mask(mode) & x))
		return -1;

	*mode_p = (*mode_p & ~S_IRWXUGO) | mode;
	return 0;
}

/**
 * richacl_compare  -  compare two acls
 *
 * Returns 0 if the two acls are identical.
 */
int
richacl_compare(const struct richacl *a1, const struct richacl *a2)
{
	const struct richace *e1, *e2;

	if (a1->a_flags != a2->a_flags ||
	    a1->a_count != a2->a_count ||
	    a1->a_owner_mask != a2->a_owner_mask ||
	    a1->a_group_mask != a2->a_group_mask ||
	    a1->a_other_mask != a2->a_other_mask)
		return -1;

	e1 = a1->a_entries;
	richacl_for_each_entry(e2, a2) {
		if (e1->e_type != e2->e_type ||
		    e1->e_flags != e2->e_flags ||
		    e1->e_mask != e2->e_mask)
			return -1;
		if (e1->e_flags & ACE4_SPECIAL_WHO) {
			if (e1->u.e_who != e2->u.e_who)
				return -1;
		} else {
			if (e1->u.e_id != e2->u.e_id)
				return -1;
		}

		e1++;
	}
	return 0;
}
