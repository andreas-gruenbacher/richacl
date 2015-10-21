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
#include "sys/richacl.h"
#include "richacl-internal.h"

/**
 * richacl_chmod  -  set the file masks of the acl
 * @mode:	file mode including the file type
 */
void richacl_chmod(struct richacl *acl, mode_t mode)
{
	unsigned int x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;

	acl->a_flags |= (RICHACL_WRITE_THROUGH | RICHACL_MASKED);
	acl->a_owner_mask = richacl_mode_to_mask(mode >> 6) & ~x;
	acl->a_group_mask = richacl_mode_to_mask(mode >> 3) & ~x;
	acl->a_other_mask = richacl_mode_to_mask(mode)      & ~x;

	if (richacl_is_auto_inherit(acl))
		acl->a_flags |= RICHACL_PROTECTED;
}
