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
 * richacl_move_everyone_aces_down  -  move everyone@ acl entries to the end
 * @alloc:	acl and number of allocated entries
 *
 * Move all everyone acl entries to the bottom of the acl so that only a
 * single everyone@ allow acl entry remains at the end, and update the
 * mask fields of all acl entries on the way. If everyone@ is not
 * granted any permissions, no empty everyone@ acl entry is inserted.
 *
 * This transformation does not modify the permissions that the acl
 * grants, but simplifies successive transformations.
 */
int
richacl_move_everyone_aces_down(struct richacl_alloc *alloc)
{
	struct richace *ace;
	unsigned int allowed = 0, denied = 0;

	richacl_for_each_entry(ace, alloc->acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				allowed |= (ace->e_mask & ~denied);
			else if (richace_is_deny(ace))
				denied |= (ace->e_mask & ~allowed);
			else
				continue;
			if (richace_change_mask(alloc, &ace, 0))
				return -1;
		} else {
			if (richace_is_allow(ace)) {
				if (richace_change_mask(alloc, &ace, allowed |
						(ace->e_mask & ~denied)))
					return -1;
			} else if (richace_is_deny(ace)) {
				if (richace_change_mask(alloc, &ace, denied |
						(ace->e_mask & ~allowed)))
					return -1;
			}
		}
	}
	if (allowed & ~RICHACE_POSIX_ALWAYS_ALLOWED) {
		struct richace *last_ace = ace - 1;

		if (alloc->acl->a_count &&
		    richace_is_everyone(last_ace) &&
		    richace_is_allow(last_ace) &&
		    richace_is_inherit_only(last_ace) &&
		    last_ace->e_mask == allowed)
			last_ace->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
		else {
			if (richacl_insert_entry(alloc, &ace))
				return -1;
			ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
			ace->e_flags = RICHACE_SPECIAL_WHO;
			ace->e_mask = allowed;
			ace->e_id = RICHACE_EVERYONE_SPECIAL_ID;
		}
	}
	return 0;
}
