/*
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

#include <errno.h>
#include "sys/richacl.h"

int richacl_valid(struct richacl *acl)
{
	struct richace *ace;

	if (acl->a_flags & ~RICHACL_VALID_FLAGS ||
	    acl->a_owner_mask & ~RICHACE_VALID_MASK ||
	    acl->a_group_mask & ~RICHACE_VALID_MASK ||
	    acl->a_other_mask & ~RICHACE_VALID_MASK)
		goto fail_einval;

	richacl_for_each_entry(ace, acl) {
		if (ace->e_type > RICHACE_ACCESS_DENIED_ACE_TYPE ||
		    ace->e_flags & ~RICHACE_VALID_FLAGS ||
		    ace->e_mask & ~RICHACE_VALID_MASK)
			goto fail_einval;
		if (ace->e_flags & RICHACE_SPECIAL_WHO &&
		    ace->e_id > RICHACE_EVERYONE_SPECIAL_ID)
			goto fail_einval;
	}
	return 0;

fail_einval:
	errno = EINVAL;
	return -1;
}
