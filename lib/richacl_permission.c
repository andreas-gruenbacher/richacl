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

#include "sys/richacl.h"
#include "richacl-internal.h"

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
