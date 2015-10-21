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

#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <errno.h>
#include <sys/xattr.h>

#include <linux/xattr.h>
#include <linux/richacl_xattr.h>

#include "sys/richacl.h"
#include "richacl-internal.h"
#include "byteorder.h"

struct richacl *richacl_from_xattr(const void *value, size_t size)
{
	const struct richacl_xattr *xattr_acl = value;
	const struct richace_xattr *xattr_ace = (void *)(xattr_acl + 1);
	struct richacl *acl = NULL;
	struct richace *ace;
	unsigned int count;
	char *xattr_ids;

	if (size < sizeof(*xattr_acl) ||
	    xattr_acl->a_version != RICHACL_XATTR_VERSION ||
	    (xattr_acl->a_flags & ~RICHACL_VALID_FLAGS))
		goto fail_einval;
	size -= sizeof(*xattr_acl);
	count = le16_to_cpu(xattr_acl->a_count);
	if (count > RICHACL_XATTR_MAX_COUNT)
		goto fail_einval;
	if (size < count * sizeof(*xattr_ace))
		goto fail_einval;
	size -= count * sizeof(*xattr_ace);

	acl = richacl_alloc(count);
	if (!acl)
		return NULL;

	acl->a_flags = xattr_acl->a_flags;
	acl->a_owner_mask = le32_to_cpu(xattr_acl->a_owner_mask);
	acl->a_group_mask = le32_to_cpu(xattr_acl->a_group_mask);
	acl->a_other_mask = le32_to_cpu(xattr_acl->a_other_mask);

	xattr_ids = (char *)(xattr_ace + count);
	if (size) {
		if (xattr_ids[size - 1] != 0)
			goto fail_einval;
	}
	richacl_for_each_entry(ace, acl) {
		ace->e_type  = le16_to_cpu(xattr_ace->e_type);
		ace->e_flags = le16_to_cpu(xattr_ace->e_flags);
		ace->e_mask  = le32_to_cpu(xattr_ace->e_mask);
		ace->e_id    = le32_to_cpu(xattr_ace->e_id);
		if (ace->e_flags & RICHACE_SPECIAL_WHO &&
		    ace->e_id > RICHACE_EVERYONE_SPECIAL_ID)
			goto fail_einval;
		if (ace->e_flags & RICHACE_UNMAPPED_WHO) {
			size_t sz;
			if (!size)
				goto fail_einval;
			sz = strlen(xattr_ids) + 1;
			ace->e_who = malloc(sz);
			if (!ace->e_who) {
				richacl_free(acl);
				errno = ENOMEM;
				return NULL;
			}
			memcpy(ace->e_who, xattr_ids, sz);
			xattr_ids += sz;
			size -= sz;
		}
		xattr_ace++;
	}

	if (size != 0)
		goto fail_einval;

	return acl;

fail_einval:
	richacl_free(acl);
	errno = EINVAL;
	return NULL;
}

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

void richacl_to_xattr(const struct richacl *acl, void *buffer)
{
	struct richacl_xattr *xattr_acl = buffer;
	struct richace_xattr *xattr_ace;
	const struct richace *ace;
	char *xattr_ids;

	xattr_acl->a_version = RICHACL_XATTR_VERSION;
	xattr_acl->a_flags = acl->a_flags;
	xattr_acl->a_count = cpu_to_le16(acl->a_count);

	xattr_acl->a_owner_mask = cpu_to_le32(acl->a_owner_mask);
	xattr_acl->a_group_mask = cpu_to_le32(acl->a_group_mask);
	xattr_acl->a_other_mask = cpu_to_le32(acl->a_other_mask);

	xattr_ace = (void *)(xattr_acl + 1);
	xattr_ids = (char *)(xattr_ace + acl->a_count);
	richacl_for_each_entry(ace, acl) {
		xattr_ace->e_type = cpu_to_le16(ace->e_type);
		xattr_ace->e_flags = cpu_to_le16(ace->e_flags &
						 RICHACE_VALID_FLAGS);
		xattr_ace->e_mask = cpu_to_le32(ace->e_mask);
		xattr_ace->e_id = cpu_to_le32(ace->e_id);
		if (ace->e_flags & RICHACE_UNMAPPED_WHO) {
			size_t sz = strlen(ace->e_who) + 1;

			memcpy(xattr_ids, ace->e_who, sz);
			xattr_ids += sz;
		}
		xattr_ace++;
	}
}

struct richacl *richacl_get_file(const char *path)
{
	void *value;
	ssize_t retval;
	struct richacl *acl;

	retval = getxattr(path, XATTR_NAME_RICHACL, NULL, 0);
	if (retval <= 0)
		return NULL;

	value = alloca(retval);
	if (!value)
		return NULL;
	retval = getxattr(path, XATTR_NAME_RICHACL, value, retval);
	if (retval < 0)
		return NULL;
	acl = richacl_from_xattr(value, retval);

	return acl;
}

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

int richacl_set_file(const char *path, const struct richacl *acl)
{
	size_t size = richacl_xattr_size(acl);
	void *value = alloca(size);

	richacl_to_xattr(acl, value);
	return setxattr(path, XATTR_NAME_RICHACL, value, size, 0);
}

int richacl_set_fd(int fd, const struct richacl *acl)
{
	size_t size = richacl_xattr_size(acl);
	void *value = alloca(size);

	richacl_to_xattr(acl, value);
	return fsetxattr(fd, XATTR_NAME_RICHACL, value, size, 0);
}
