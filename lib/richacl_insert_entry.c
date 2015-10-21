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

#include <stdlib.h>
#include <string.h>
#include "sys/richacl.h"
#include "richacl-internal.h"

/**
 * richacl_insert_entry  -  insert an entry in an acl
 * @alloc:	acl and number of allocated entries
 * @ace:	entry before which the new entry shall be inserted
 *
 * Insert a new entry in @alloc->acl at position @ace, and zero-initialize
 * it.  This may require reallocating @alloc->acl.
 */
int
richacl_insert_entry(struct richacl_alloc *alloc, struct richace **ace)
{
	int n = *ace - alloc->acl->a_entries;

	if (alloc->count == alloc->acl->a_count) {
		size_t size = sizeof(struct richacl) +
			      (alloc->count + 1) * sizeof(struct richace);
		struct richacl *acl2;

		acl2 = realloc(alloc->acl, size);
		if (!acl2)
			return -1;
		alloc->count++;
		alloc->acl = acl2;
		*ace = acl2->a_entries + n;
	}
	memmove(*ace + 1, *ace, sizeof(struct richace) * (alloc->acl->a_count - n));
	memset(*ace, 0, sizeof(struct richace));
	alloc->acl->a_count++;
	return 0;
}
