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
#include "sys/richacl.h"
#include "richacl-internal.h"

struct richacl *
richacl_auto_inherit(const struct richacl *acl,
		     const struct richacl *inherited_acl)
{
	struct richacl_alloc alloc = {
		.acl = richacl_clone(acl),
		.count = acl->a_count,
	};
	const struct richace *inherited_ace;
	struct richace *ace;

	richacl_for_each_entry(ace, alloc.acl) {
		if (ace->e_flags & RICHACE_INHERITED_ACE)
			richacl_delete_entry(&alloc, &ace);
	}
	richacl_for_each_entry(inherited_ace, inherited_acl) {
		ace = richacl_append_entry(&alloc);
		if (!ace)
			return NULL;
		if (richace_copy(ace, inherited_ace)) {
			richacl_free(alloc.acl);
			return NULL;
		}
		ace->e_flags |= RICHACE_INHERITED_ACE;
	}
	return alloc.acl;
}
