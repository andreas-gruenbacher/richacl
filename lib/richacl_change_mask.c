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
 * richace_change_mask  -  change the mask in @ace to @mask
 * @alloc:	acl and number of allocated entries
 * @ace:	entry to modify
 * @mask:	new mask for @ace
 *
 * Set the effective mask of @ace to @mask. This will require splitting
 * off a separate acl entry if @ace is inheritable. In that case, the
 * effective- only acl entry is inserted after the inheritable acl
 * entry, end the inheritable acl entry is set to inheritable-only. If
 * @mode is 0, either set the original acl entry to inheritable-only if
 * it was inheritable, or remove it otherwise.  The returned @ace points
 * to the modified or inserted effective-only acl entry if that entry
 * exists, to the entry that has become inheritable-only, or else to the
 * previous entry in the acl. This is the expected behavior when
 * modifying masks while forward iterating over an acl.
 */
int
richace_change_mask(struct richacl_alloc *alloc, struct richace **ace,
		    unsigned int mask)
{
	if (mask && (*ace)->e_mask == mask)
		(*ace)->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
	else if (mask & ~RICHACE_POSIX_ALWAYS_ALLOWED) {
		if (richace_is_inheritable(*ace)) {
			if (richacl_insert_entry(alloc, ace))
				return -1;
			if (richace_copy(*ace, *ace + 1))
				return -1;
			(*ace)->e_flags |= RICHACE_INHERIT_ONLY_ACE;
			(*ace)++;
			(*ace)->e_flags &= ~RICHACE_INHERITANCE_FLAGS |
					   RICHACE_INHERITED_ACE;
		}
		(*ace)->e_mask = mask;
	} else {
		if (richace_is_inheritable(*ace))
			(*ace)->e_flags |= RICHACE_INHERIT_ONLY_ACE;
		else
			richacl_delete_entry(alloc, ace);
	}
	return 0;
}
