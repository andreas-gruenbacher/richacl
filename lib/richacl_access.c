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
#include <errno.h>
#include "sys/richacl.h"
#include "richacl-internal.h"

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
			goto entry_matches_owner;
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
