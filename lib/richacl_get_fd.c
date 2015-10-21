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
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include "sys/richacl.h"

struct richacl *richacl_get_fd(int fd)
{
	void *value;
	ssize_t retval;
	struct richacl *acl;

	retval = fgetxattr(fd, XATTR_NAME_RICHACL, NULL, 0);
	if (retval <= 0)
		return NULL;

	value = alloca(retval);
	if (!value)
		return NULL;
	retval = fgetxattr(fd, XATTR_NAME_RICHACL, value, retval);
	if (retval < 0)
		return NULL;
	acl = richacl_from_xattr(value, retval);

	return acl;
}
