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

#include <string.h>
#include "sys/richacl.h"
#include <linux/richacl_xattr.h>

size_t richacl_xattr_size(const struct richacl *acl)
{
	size_t size = sizeof(struct richacl_xattr);
	const struct richace *ace;

	size += sizeof(struct richace_xattr) * acl->a_count;
	richacl_for_each_entry(ace, acl) {
		if (ace->e_flags & RICHACE_UNMAPPED_WHO)
			size += strlen(ace->e_who) + 1;
	}
	return size;
}
