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
