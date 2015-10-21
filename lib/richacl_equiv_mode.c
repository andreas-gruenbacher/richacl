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

#include <sys/stat.h>
#include "sys/richacl.h"
#include "richacl-internal.h"

#ifndef S_IRWXUGO
# define S_IRWXUGO (S_IRWXU | S_IRWXG | S_IRWXO)
#endif

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
