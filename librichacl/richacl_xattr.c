/*
  Copyright (C) 2006, 2009, 2010  Novell, Inc.
  Written by Andreas Gruenbacher <agruen@suse.de>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <attr/xattr.h>
#include "richacl.h"
#include "richacl_xattr.h"
#include "richacl-internal.h"
#include "byteorder.h"

static struct richacl *richacl_from_xattr(const void *value, size_t size)
{
	const struct richacl_xattr *xattr_acl = value;
	const struct richace_xattr *xattr_ace = (void *)(xattr_acl + 1);
	struct richacl *acl = NULL;
	struct richace *ace;
	int count;

	if (size < sizeof(struct richacl_xattr) ||
	    xattr_acl->a_version != ACL4_XATTR_VERSION)
		goto fail_einval;

	count = le16_to_cpu(xattr_acl->a_count);
	if (count > ACL4_XATTR_MAX_COUNT)
		goto fail_einval;

	acl = richacl_alloc(count);
	if (!acl)
		return NULL;

	acl->a_flags = xattr_acl->a_flags;
	acl->a_owner_mask = le32_to_cpu(xattr_acl->a_owner_mask);
	acl->a_group_mask = le32_to_cpu(xattr_acl->a_group_mask);
	acl->a_other_mask = le32_to_cpu(xattr_acl->a_other_mask);

	richacl_for_each_entry(ace, acl) {
		const char *who = (void *)(xattr_ace + 1), *end;
		ssize_t used = (void *)who - value;

		if (used > size)
			goto fail_einval;
		end = memchr(who, 0, size - used);
		if (!end)
			goto fail_einval;

		ace->e_type = le16_to_cpu(xattr_ace->e_type);
		ace->e_flags = le16_to_cpu(xattr_ace->e_flags);
		ace->e_mask = le32_to_cpu(xattr_ace->e_mask);
		ace->u.e_id = le32_to_cpu(xattr_ace->e_id);

		if (who == end) {
			if (ace->u.e_id == -1)
				goto fail_einval;  /* uid/gid needed */
		} else if (richace_set_who(ace, who))
			goto fail_einval;

		xattr_ace = (void *)who + ALIGN(end - who + 1, 4);
	}

	return acl;

fail_einval:
	richacl_free(acl);
	errno = EINVAL;
	return NULL;
}

static size_t richacl_xattr_size(const struct richacl *acl)
{
	size_t size = sizeof(struct richacl_xattr);
	const struct richace *ace;

	richacl_for_each_entry(ace, acl) {
		size += sizeof(struct richace_xattr) +
			(richace_get_who(ace) ?
			 ALIGN(strlen(ace->u.e_who) + 1, 4) : 4);
	}
	return size;
}

static void richacl_to_xattr(const struct richacl *acl, void *buffer)
{
	struct richacl_xattr *xattr_acl = buffer;
	struct richace_xattr *xattr_ace;
	const struct richace *ace;

	xattr_acl->a_version = ACL4_XATTR_VERSION;
	xattr_acl->a_flags = acl->a_flags;
	xattr_acl->a_count = cpu_to_le16(acl->a_count);

	xattr_acl->a_owner_mask = cpu_to_le32(acl->a_owner_mask);
	xattr_acl->a_group_mask = cpu_to_le32(acl->a_group_mask);
	xattr_acl->a_other_mask = cpu_to_le32(acl->a_other_mask);

	xattr_ace = (void *)(xattr_acl + 1);
	richacl_for_each_entry(ace, acl) {
		xattr_ace->e_type = cpu_to_le16(ace->e_type);
		xattr_ace->e_flags =
			cpu_to_le16(ace->e_flags & ACE4_VALID_FLAGS);
		xattr_ace->e_mask = cpu_to_le32(ace->e_mask);
		if (richace_get_who(ace)) {
			int sz = ALIGN(strlen(ace->u.e_who) + 1, 4);

			xattr_ace->e_id = cpu_to_le32(-1);
			memset(xattr_ace->e_who + sz - 4, 0, 4);
			strcpy(xattr_ace->e_who, ace->u.e_who);
			xattr_ace = (void *)xattr_ace->e_who + sz;
		} else {
			xattr_ace->e_id = cpu_to_le32(ace->u.e_id);
			memset(xattr_ace->e_who, 0, 4);
			xattr_ace = (void *)xattr_ace->e_who + 4;
		}
	}
}

struct richacl *richacl_get_file(const char *path)
{
	void *value;
	ssize_t retval;
	struct richacl *acl;

	retval = getxattr(path, SYSTEM_RICHACL, NULL, 0);
	if (retval <= 0)
		return NULL;

	value = alloca(retval);
	if (!value)
		return NULL;
	retval = getxattr(path, SYSTEM_RICHACL, value, retval);
	acl = richacl_from_xattr(value, retval);

	return acl;
}

struct richacl *richacl_get_fd(int fd)
{
	void *value;
	ssize_t retval;
	struct richacl *acl;

	retval = fgetxattr(fd, SYSTEM_RICHACL, NULL, 0);
	if (retval <= 0)
		return NULL;

	value = alloca(retval);
	if (!value)
		return NULL;
	retval = fgetxattr(fd, SYSTEM_RICHACL, value, retval);
	acl = richacl_from_xattr(value, retval);

	return acl;
}

int richacl_set_file(const char *path, const struct richacl *acl)
{
	size_t size = richacl_xattr_size(acl);
	void *value = alloca(size);

	richacl_to_xattr(acl, value);
	return setxattr(path, SYSTEM_RICHACL, value, size, 0);
}

int richacl_set_fd(int fd, const struct richacl *acl)
{
	size_t size = richacl_xattr_size(acl);
	void *value = alloca(size);

	richacl_to_xattr(acl, value);
	return fsetxattr(fd, SYSTEM_RICHACL, value, size, 0);
}
