/*
 * Copyright (C) 2006, 2010  Novell, Inc.
 * Copyright (C) 2015  Red Hat, Inc.
 * Written by Andreas Gruenbacher <agruenba@redhat.com>
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef __UAPI_RICHACL_XATTR_H
#define __UAPI_RICHACL_XATTR_H

#include <linux/types.h>
#include <linux/limits.h>

struct richace_xattr {
	__le16	e_type;
	__le16	e_flags;
	__le32	e_mask;
	__le32	e_id;
};

struct richacl_xattr {
	__u8	a_version;
	__u8	a_flags;
	__le16	a_count;
	__le32	a_owner_mask;
	__le32	a_group_mask;
	__le32	a_other_mask;
};

#define RICHACL_XATTR_VERSION 0
#define RICHACL_XATTR_MAX_COUNT \
	((XATTR_SIZE_MAX - sizeof(struct richacl_xattr)) / \
	 sizeof(struct richace_xattr))

#endif  /* __UAPI_RICHACL_XATTR_H */
