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
 * richacl_append_entry  -  append an entry to an acl
 * @alloc:	acl and number of allocated entries
 *
 * Append a new entry to @alloc->acl and zero-initialize it.
 * This may require reallocating @alloc->acl.
 */
struct richace *
richacl_append_entry(struct richacl_alloc *alloc)
{
	struct richace *ace;

	if (alloc->count == alloc->acl->a_count) {
		size_t size = sizeof(struct richacl) +
			      (alloc->count + 1) * sizeof(struct richace);
		struct richacl *acl2;

		acl2 = realloc(alloc->acl, size);
		if (!acl2)
			return NULL;
		alloc->count++;
		alloc->acl = acl2;
	}
	ace = alloc->acl->a_entries + alloc->acl->a_count;
	alloc->acl->a_count++;
	memset(ace, 0, sizeof(struct richace));
	return ace;
}
