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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "richacl.h"
#include "richacl-internal.h"

#ifndef S_IRWXUGO
# define S_IRWXUGO (S_IRWXU | S_IRWXG | S_IRWXO)
#endif

const char *richace_owner_who	 = "OWNER@";
const char *richace_group_who	 = "GROUP@";
const char *richace_everyone_who = "EVERYONE@";

bool richace_is_same_identifier(const struct richace *ace1,
				const struct richace *ace2)
{
	return !((ace1->e_flags ^ ace2->e_flags) &
		 (RICHACE_SPECIAL_WHO |
		  RICHACE_IDENTIFIER_GROUP |
		  RICHACE_UNMAPPED_WHO)) &&
	       ((ace1->e_flags & RICHACE_UNMAPPED_WHO) ?
	        !strcmp(ace1->e_who, ace2->e_who) :
		ace1->e_id == ace2->e_id);
}

bool richace_is_owner(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
		ace->e_id == RICHACE_OWNER_SPECIAL_ID;
}

bool richace_is_group(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
		ace->e_id == RICHACE_GROUP_SPECIAL_ID;
}

bool richace_is_everyone(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
		ace->e_id == RICHACE_EVERYONE_SPECIAL_ID;
}

struct richacl *richacl_alloc(unsigned int count)
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
	struct richace *ace2;

	if (!acl)
		return NULL;
	size = sizeof(struct richacl) + acl->a_count * sizeof(struct richace);
	acl2 = malloc(size);
	if (acl2)
		memcpy(acl2, acl, size);
	richacl_for_each_entry(ace2, acl2) {
		if (ace2->e_flags & RICHACE_UNMAPPED_WHO) {
			ace2->e_who = strdup(ace2->e_who);
			if (!ace2->e_who) {
				while (ace2 != acl->a_entries) {
					ace2--;
					if (ace2->e_flags & RICHACE_UNMAPPED_WHO)
						free(ace2->e_who);
				}
				free(acl2);
				return NULL;
			}
		}
	}
	return acl2;
}

void richacl_free(struct richacl *acl)
{
	if (acl) {
		struct richace *ace;

		richacl_for_each_entry(ace, acl) {
			if (ace->e_flags & RICHACE_UNMAPPED_WHO)
				free(ace->e_who);
		}
		free(acl);
	}
}

/**
 * richacl_allowed_to_who  -  mask flags allowed to a specific who value
 *
 * Computes the mask values allowed to a specific who value, taking
 * everyone@ entries into account.
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
	 * result in a group mask of rw:
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

	acl->a_flags &= ~(RICHACL_WRITE_THROUGH | RICHACL_MASKED);
}

int richace_set_special_who(struct richace *ace, const char *who)
{
	int id;
	if (!strcmp(who, richace_owner_who))
		id = RICHACE_OWNER_SPECIAL_ID;
	else if (!strcmp(who, richace_group_who))
		id = RICHACE_GROUP_SPECIAL_ID;
	else if (!strcmp(who, richace_everyone_who))
		id = RICHACE_EVERYONE_SPECIAL_ID;
	else
		return -1;

	ace->e_id = id;
	ace->e_flags |= RICHACE_SPECIAL_WHO;
	/*
	 * Also clear the RICHACE_IDENTIFIER_GROUP flag for ACEs with a special
	 * who value: richace_is_same_identifier() relies on that.
	 */
	ace->e_flags &= ~(RICHACE_IDENTIFIER_GROUP |
			  RICHACE_UNMAPPED_WHO);
	return 0;
}

void richace_set_uid(struct richace *ace, uid_t uid)
{
	if (ace->e_flags & RICHACE_UNMAPPED_WHO)
		free(ace->e_who);
	ace->e_id = uid;
	ace->e_flags &= ~(RICHACE_SPECIAL_WHO |
			  RICHACE_IDENTIFIER_GROUP |
			  RICHACE_UNMAPPED_WHO);
}

void richace_set_gid(struct richace *ace, gid_t gid)
{
	if (ace->e_flags & RICHACE_UNMAPPED_WHO)
		free(ace->e_who);
	ace->e_id = gid;
	ace->e_flags &= ~(RICHACE_SPECIAL_WHO |
			  RICHACE_UNMAPPED_WHO);
	ace->e_flags |= RICHACE_IDENTIFIER_GROUP;
}

int richace_set_unmapped_who(struct richace *ace, const char *who, unsigned int who_flags)
{
	unsigned short flags = ace->e_flags & ~RICHACE_UNMAPPED_WHO;
	char *who_dup = NULL;

	if (who) {
		who_dup = strdup(who);
		if (!who_dup)
			return -1;
		flags |= RICHACE_UNMAPPED_WHO;
		flags &= ~RICHACE_IDENTIFIER_GROUP;
		if (who_flags & RICHACE_IDENTIFIER_GROUP)
			flags |= RICHACE_IDENTIFIER_GROUP;
	}
	if (ace->e_flags & RICHACE_UNMAPPED_WHO)
		free(ace->e_who);
	ace->e_flags = flags;
	ace->e_who = who_dup;
	return 0;
}

int richace_copy(struct richace *dst, const struct richace *src)
{
	char *who = src->e_who;

	if (src->e_flags & RICHACE_UNMAPPED_WHO) {
		who = strdup(who);
		if (!who)
			return -1;
	}
	if (dst->e_flags & RICHACE_UNMAPPED_WHO)
		free(dst->e_who);
	memcpy(dst, src, sizeof(struct richace));
	dst->e_who = who;
	return 0;
}

void richace_free(struct richace *ace)
{
	if (ace->e_flags & RICHACE_UNMAPPED_WHO) {
		free(ace->e_who);
		ace->e_flags &= ~RICHACE_UNMAPPED_WHO;
		ace->e_id = 0;
	}
}

/**
 * richacl_mode_to_mask  - compute a file mask from the lowest three mode bits
 *
 * See richacl_masks_to_mode().
 */
static unsigned int richacl_mode_to_mask(mode_t mode)
{
	unsigned int mask = 0;

	if (mode & S_IROTH)
		mask |= RICHACE_POSIX_MODE_READ;
	if (mode & S_IWOTH)
		mask |= RICHACE_POSIX_MODE_WRITE;
	if (mode & S_IXOTH)
		mask |= RICHACE_POSIX_MODE_EXEC;

	return mask;
}

/**
 * richacl_chmod  -  set the file masks of the acl
 * @mode:	file mode including the file type
 */
void richacl_chmod(struct richacl *acl, mode_t mode)
{
	unsigned int x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;

	acl->a_flags |= (RICHACL_WRITE_THROUGH | RICHACL_MASKED);
	acl->a_owner_mask = richacl_mode_to_mask(mode >> 6) & ~x;
	acl->a_group_mask = richacl_mode_to_mask(mode >> 3) & ~x;
	acl->a_other_mask = richacl_mode_to_mask(mode)      & ~x;

	if (richacl_is_auto_inherit(acl))
		acl->a_flags |= RICHACL_PROTECTED;
}

/**
 * richacl_from_mode  -  create an acl which corresponds to @mode
 * @mode:	file mode including the file type
 */
struct richacl *richacl_from_mode(mode_t mode)
{
	unsigned int owner_mask = richacl_mode_to_mask(mode >> 6);
	unsigned int group_mask = richacl_mode_to_mask(mode >> 3);
	unsigned int other_mask = richacl_mode_to_mask(mode);
	unsigned int denied;
	unsigned int entries = 0;
	struct richacl *acl;
	struct richace *ace;

	/* RICHACE_DELETE_CHILD is meaningless for non-directories. */
	if (!S_ISDIR(mode)) {
		owner_mask &= ~RICHACE_DELETE_CHILD;
		group_mask &= ~RICHACE_DELETE_CHILD;
		other_mask &= ~RICHACE_DELETE_CHILD;
	}

	denied = ~owner_mask & (group_mask | other_mask);
	if (denied)
		entries++;  /* owner@ deny entry needed */
	if (owner_mask & ~(group_mask & other_mask))
		entries++;  /* owner@ allow entry needed */
	denied = ~group_mask & other_mask;
	if (denied)
		entries++;  /* group@ deny entry needed */
	if (group_mask & ~other_mask)
		entries++;  /* group@ allow entry needed */
	if (other_mask)
		entries++;  /* everyone@ allow entry needed */

	acl = richacl_alloc(entries);
	if (!acl)
		return NULL;
	acl->a_owner_mask = owner_mask;
	acl->a_group_mask = group_mask;
	acl->a_other_mask = other_mask;
	ace = acl->a_entries;

	denied = ~owner_mask & (group_mask | other_mask);
	if (denied) {
		ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = denied;
		ace->e_id = RICHACE_OWNER_SPECIAL_ID;
		ace++;
	}
	if (owner_mask & ~(group_mask & other_mask)) {
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = owner_mask;
		ace->e_id = RICHACE_OWNER_SPECIAL_ID;
		ace++;
	}
	denied = ~group_mask & other_mask;
	if (denied) {
		ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = denied;
		ace->e_id = RICHACE_GROUP_SPECIAL_ID;
		ace++;
	}
	if (group_mask & ~other_mask) {
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = group_mask;
		ace->e_id = RICHACE_GROUP_SPECIAL_ID;
		ace++;
	}
	if (other_mask) {
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = other_mask;
		ace->e_id = RICHACE_EVERYONE_SPECIAL_ID;
		ace++;
	}

	return acl;
}

bool richace_is_unix_user(const struct richace *ace)
{
	return !(ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       !(ace->e_flags & RICHACE_IDENTIFIER_GROUP);
}

bool richace_is_unix_group(const struct richace *ace)
{
	return !(ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       (ace->e_flags & RICHACE_IDENTIFIER_GROUP);
}

static int in_groups(gid_t group, const gid_t groups[], int n_groups)
{
	int n;

	for (n = 0; n < n_groups; n++)
		if (group == groups[n])
			return 1;
	return 0;
}

/**
 * richacl_access  -  Determine the permissions of a "process"
 * @file:	file name
 * @st:		status of file @file (or NULL)
 * @user:	user to check permissions for
 * @groups:	groups the user is in
 * @n_groups:	number of groups in @groups (or negative)
 *
 * Returns the permissions granted to a process which is owned by user @user and
 * which is in groups @groups.  If @stat is NULL, stat() is called on @file.
 * If @n_groups is negative, the groups the calling process is in are used.
 * Returns -1 and sets errno on error.
 */
int richacl_access(const char *file, const struct stat *st, uid_t user,
		   const gid_t *groups, int n_groups)
{
	const struct richacl *acl;
	const struct richace *ace;
	struct stat local_st;
	unsigned int mask = RICHACE_VALID_MASK, allowed = 0;
	int in_owning_group;
	int in_owner_or_group_class;
	gid_t *groups_alloc = NULL;

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
		groups_alloc = malloc(sizeof(gid_t) * (n_groups + 1));
		if (!groups_alloc)
			return -1;
		groups_alloc[0] = getegid();
		if (getgroups(n_groups, groups_alloc + 1) < 0) {
			free(groups_alloc);
			return -1;
		}
		groups = groups_alloc;
	}

	in_owning_group = in_groups(st->st_gid, groups, n_groups);
	in_owner_or_group_class = in_owning_group;

	/*
	 * A process is
	 *   - in the owner file class if it owns the file,
	 *   - in the group file class if it is in the file's owning group or
	 *     it matches any of the user or group entries, and
	 *   - in the other file class otherwise.
	 * The file class is only relevant for determining which file mask to
	 * apply, which only happens for masked acls.
	 */

	if (acl->a_flags & RICHACL_MASKED) {
		if ((acl->a_flags & RICHACL_WRITE_THROUGH) && user == st->st_uid)
			return acl->a_owner_mask;
	} else {
		/*
		 * We don't care which class the process is in when the
		 * acl is not masked.
		 */
		in_owner_or_group_class = 1;
	}

	richacl_for_each_entry(ace, acl) {
		unsigned int ace_mask = ace->e_mask;

		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_owner(ace)) {
			if (user != st->st_uid)
				continue;
			goto entry_matches_owner;
		} else if (richace_is_group(ace)) {
			if (!in_owning_group)
				continue;
		} else if (richace_is_unix_user(ace)) {
			if (user != ace->e_id)
				continue;
		} else if (richace_is_unix_group(ace)) {
			if (!in_groups(ace->e_id, groups, n_groups))
				continue;
		} else if (richace_is_everyone(ace))
			goto entry_matches_everyone;
		else
			continue;

		/*
		 * Apply the group file mask to entries other than owner@ and
		 * everyone@ or user entries matching the owner.  This ensures
		 * that we grant the same permissions as the acl computed by
		 * richacl_apply_masks().
		 *
		 * Without this restriction, the following richacl would grant
		 * rw access to processes which are both the owner and in the
		 * owning group, but not to other users in the owning group,
		 * which could not be represented without masks:
		 *
		 *  owner:rw::mask
		 *  group@:rw::allow
		 */
		if ((acl->a_flags & RICHACL_MASKED) && richace_is_allow(ace))
			ace_mask &= acl->a_group_mask;

entry_matches_owner:
		/* The process is in the owner or group file class. */
		in_owner_or_group_class = 1;

entry_matches_everyone:
		/* Check which mask flags the ACE allows or denies. */
		if (richace_is_allow(ace))
			allowed |= ace_mask & mask;
		mask &= ~ace_mask;
		if (!mask && in_owner_or_group_class)
			break;
	}

	if (acl->a_flags & RICHACL_MASKED) {
		/*
		 * Figure out which file mask applies.
		 */
		if (user == st->st_uid)
			allowed &= acl->a_owner_mask;
		else if (in_owner_or_group_class)
			allowed &= acl->a_group_mask;
		else {
			if (acl->a_flags & RICHACL_WRITE_THROUGH)
				allowed = acl->a_other_mask;
			else
				allowed &= acl->a_other_mask;
		}
	}

	/* RICHACE_DELETE_CHILD is meaningless for non-directories. */
	if (!S_ISDIR(st->st_mode))
		allowed &= ~RICHACE_DELETE_CHILD;

	if (groups != groups_alloc)
		free(groups_alloc);

	return allowed;
}

/**
 * richacl_permission  -  check if a user has the requested access
 * @acl:	ACL of the file to check
 * @owner:	Owner of the file
 * @owning_group: Owning group of the file
 * @user:	User ID of the accessing process
 * @groups:	Group IDs the accessing process is a member in
 * @n_groups:	Number of entries in @groups
 * @mask:	Requested permissions (RICHACE_* mask flags)
 *
 * Returns true if the requiested permissions are allowed.
 */
bool richacl_permission(struct richacl *acl, uid_t owner, gid_t owning_group,
			uid_t user, const gid_t *groups, int n_groups,
			unsigned int mask)
{
	const struct richace *ace;
	unsigned int requested = mask;
	int in_owning_group = in_groups(owning_group, groups, n_groups);
	int in_owner_or_group_class = in_owning_group;

        /*
	 * A process is
	 *   - in the owner file class if it owns the file,
	 *   - in the group file class if it is in the file's owning group or
	 *     it matches any of the user or group entries, and
	 *   - in the other file class otherwise.
	 * The file class is only relevant for determining which file mask to
	 * apply, which only happens for masked acls.
	 */

	if (acl->a_flags & RICHACL_MASKED) {
		if ((acl->a_flags & RICHACL_WRITE_THROUGH) && user == owner)
			return !(requested & ~acl->a_owner_mask);
	} else {
		/*
		 * We don't care which class the process is in when the
		 * acl is not masked.
		 */
		in_owner_or_group_class = 1;
	}

	/*
	 * Check if the acl grants the requested access and determine which
	 * file class the process is in.
	 */
	richacl_for_each_entry(ace, acl) {
		unsigned int ace_mask = ace->e_mask;

		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_owner(ace)) {
			if (user != owner)
				continue;
			goto entry_matches_owner;
		} else if (richace_is_group(ace)) {
			if (!in_owning_group)
				continue;
		} else if (richace_is_unix_user(ace)) {
			if (user != ace->e_id)
				continue;
		} else if (richace_is_unix_group(ace)) {
			if (!in_groups(ace->e_id, groups, n_groups))
				continue;
		} else if (richace_is_everyone(ace))
			goto entry_matches_everyone;
		else
			continue;

		/*
		 * Apply the group file mask to entries other than owner@ and
		 * everyone@ or user entries matching the owner.  This ensures
		 * that we grant the same permissions as the acl computed by
		 * richacl_apply_masks().
		 *
		 * Without this restriction, the following richacl would grant
		 * rw access to processes which are both the owner and in the
		 * owning group, but not to other users in the owning group,
		 * which could not be represented without masks:
		 *
		 *  owner:rw::mask
		 *  group@:rw::allow
		 */
		if ((acl->a_flags & RICHACL_MASKED) && richace_is_allow(ace))
			ace_mask &= acl->a_group_mask;

entry_matches_owner:
		/* The process is in the owner or group file class. */
		in_owner_or_group_class = 1;

entry_matches_everyone:
		/* Check which mask flags the ACE allows or denies. */
		if (richace_is_deny(ace) && (ace_mask & mask))
			return false;
		mask &= ~ace_mask;

		/*
		 * Keep going until we know which file class
		 * the process is in.
		 */
		if (!mask && in_owner_or_group_class)
			break;
	}

	if (acl->a_flags & RICHACL_MASKED) {
		/*
		 * The file class a process is in determines which file mask
		 * applies.  Check if that file mask also grants the requested
		 * access.
		 */
		if (user == owner) {
			if (requested & ~acl->a_owner_mask)
				return false;
		} else if (in_owner_or_group_class) {
			if (requested & ~acl->a_group_mask)
				return false;
		} else {
			if (acl->a_flags & RICHACL_WRITE_THROUGH)
				return !(requested & ~acl->a_other_mask);
			else if (requested & ~acl->a_other_mask)
				return false;
		}
	}

	return !mask;
}

/**
 * richacl_mask_to_mode  -  compute the file permission bits which correspond to @mask
 * @mask:	%RICHACE_* permission mask
 *
 * See richacl_masks_to_mode().
 */
static int
richacl_mask_to_mode(unsigned int mask)
{
	int mode = 0;

	if (mask & RICHACE_POSIX_MODE_READ)
		mode |= S_IROTH;
	if (mask & RICHACE_POSIX_MODE_WRITE)
		mode |= S_IWOTH;
	if (mask & RICHACE_POSIX_MODE_EXEC)
		mode |= S_IXOTH;

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
 * a mask contains RICHACE_APPEND_DATA even if it does not also contain
 * RICHACE_WRITE_DATA.
 *
 * Permissions which are not in RICHACE_POSIX_MODE_READ, RICHACE_POSIX_MODE_WRITE, or
 * RICHACE_POSIX_MODE_EXEC cannot be represented in the file permission bits.
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
 * a new file.  If there is no inheritable acl, it will return an empty acl.
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
		acl = richacl_alloc(count);
		if (!acl)
			return NULL;
		ace = acl->a_entries;
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!richace_is_inheritable(dir_ace))
				continue;
			if (richace_copy(ace, dir_ace))
				goto fail;
			if (dir_ace->e_flags & RICHACE_NO_PROPAGATE_INHERIT_ACE)
				richace_clear_inheritance_flags(ace);
			else if (!(dir_ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE))
				ace->e_flags |= RICHACE_INHERIT_ONLY_ACE;
			ace++;
		}
	} else {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & RICHACE_FILE_INHERIT_ACE))
				continue;
			count++;
		}
		acl = richacl_alloc(count);
		if (!acl)
			return NULL;
		ace = acl->a_entries;
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & RICHACE_FILE_INHERIT_ACE))
				continue;
			if (richace_copy(ace, dir_ace))
				goto fail;
			richace_clear_inheritance_flags(ace);
			/*
			 * RICHACE_DELETE_CHILD is meaningless for
			 * non-directories, so clear it.
			 */
			ace->e_mask &= ~RICHACE_DELETE_CHILD;
			ace++;
		}
	}

	if (richacl_is_auto_inherit(dir_acl)) {
		acl->a_flags = RICHACL_AUTO_INHERIT;
		richacl_for_each_entry(ace, acl)
			ace->e_flags |= RICHACE_INHERITED_ACE;
	}

	return acl;

fail:
	richacl_free(acl);
	return NULL;
}

/**
 * richacl_equiv_mode  -  compute the mode equivalent of @acl
 *
 * An acl is considered equivalent to a file mode if it only consists of
 * owner@, group@, and everyone@ entries and the owner@ permissions do not
 * depend on whether the owner is a member in the owning group.
 *
 * The file type in @mode_p must be set when calling richacl_equiv_mode().
 *
 * Returns with 0 if @acl is equivalent to a file mode; in that case, the
 * file permission bits in @mode_p are set to the mode equivalent of @acl.
 */
int
richacl_equiv_mode(const struct richacl *acl, mode_t *mode_p)
{
	mode_t mode = *mode_p;

	/*
	 * The RICHACE_DELETE_CHILD flag is meaningless for non-directories, so
	 * we ignore it.
	 */
	unsigned int x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;
	struct {
		unsigned int allowed;
		unsigned int defined;  /* allowed or denied */
	} owner = {
		.defined = RICHACE_POSIX_ALWAYS_ALLOWED | RICHACE_POSIX_OWNER_ALLOWED | x,
	}, group = {
		.defined = RICHACE_POSIX_ALWAYS_ALLOWED | x,
	}, everyone = {
		.defined = RICHACE_POSIX_ALWAYS_ALLOWED | x,
	};
	const struct richace *ace;

	if (acl->a_flags & ~(RICHACL_WRITE_THROUGH | RICHACL_MASKED))
		return -1;

	richacl_for_each_entry(ace, acl) {
		if (ace->e_flags & ~RICHACE_SPECIAL_WHO)
			return -1;

		if (richace_is_owner(ace) || richace_is_everyone(ace)) {
			x = ace->e_mask & ~owner.defined;
			if (richace_is_allow(ace)) {
				unsigned int group_denied = group.defined & ~group.allowed;

				if (x & group_denied)
					return -1;
				owner.allowed |= x;
			} else /* if (richace_is_deny(ace)) */ {
				if (x & group.allowed)
					return -1;
			}
			owner.defined |= x;

			if (richace_is_everyone(ace)) {
				x = ace->e_mask;
				if (richace_is_allow(ace)) {
					group.allowed |= x & ~group.defined;
					everyone.allowed |= x & ~everyone.defined;
				}
				group.defined |= x;
				everyone.defined |= x;
			}
		} else if (richace_is_group(ace)) {
			x = ace->e_mask & ~group.defined;
			if (richace_is_allow(ace))
				group.allowed |= x;
			group.defined |= x;
		} else
			return -1;
	}

	if (group.allowed & ~owner.defined)
		return -1;

	if (acl->a_flags & RICHACL_MASKED) {
		if (acl->a_flags & RICHACL_WRITE_THROUGH) {
			owner.allowed = acl->a_owner_mask;
			everyone.allowed = acl->a_other_mask;
		} else {
			owner.allowed &= acl->a_owner_mask;
			everyone.allowed &= acl->a_other_mask;
		}
		group.allowed &= acl->a_group_mask;
	}

	mode = (mode & ~S_IRWXUGO) |
	       (richacl_mask_to_mode(owner.allowed) << 6) |
	       (richacl_mask_to_mode(group.allowed) << 3) |
		richacl_mask_to_mode(everyone.allowed);

	/* Mask flags we can ignore */
	x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;

        if (((richacl_mode_to_mask(mode >> 6) ^ owner.allowed)    & ~x) ||
            ((richacl_mode_to_mask(mode >> 3) ^ group.allowed)    & ~x) ||
            ((richacl_mode_to_mask(mode)      ^ everyone.allowed) & ~x))
		return -1;

	*mode_p = mode;
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
		if (e1->e_id != e2->e_id)
			return -1;
		e1++;
	}
	return 0;
}
