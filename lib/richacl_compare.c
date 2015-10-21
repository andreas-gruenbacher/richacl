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

/**
 * richacl_compare  -  compare two acls
 *
 * Returns 0 if the two acls are identical.
 */
int
richacl_compare(const struct richacl *a1, const struct richacl *a2)
{
	const struct richace *e1, *e2;

	if (a1->a_flags != a2->a_flags ||
	    a1->a_count != a2->a_count ||
	    a1->a_owner_mask != a2->a_owner_mask ||
	    a1->a_group_mask != a2->a_group_mask ||
	    a1->a_other_mask != a2->a_other_mask)
		return -1;

	e1 = a1->a_entries;
	richacl_for_each_entry(e2, a2) {
		if (e1->e_type != e2->e_type ||
		    e1->e_flags != e2->e_flags ||
		    e1->e_mask != e2->e_mask)
			return -1;
		if (e1->e_id != e2->e_id)
			return -1;
		e1++;
	}
	return 0;
}
