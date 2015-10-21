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
#include <stdlib.h>
#include "sys/richacl.h"
#include "richacl-internal.h"

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
