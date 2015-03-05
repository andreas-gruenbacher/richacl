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

#ifndef __RICHACL_XATTR_H
#define __RICHACL_XATTR_H

#include <arpa/inet.h>
#include <stdint.h>

struct richace_xattr {
	uint16_t	e_type;
	uint16_t	e_flags;
	uint32_t	e_mask;
	uint32_t	e_id;
};

struct richacl_xattr {
	unsigned char	a_version;
	unsigned char	a_flags;
	uint16_t	a_unused;
	uint32_t	a_owner_mask;
	uint32_t	a_group_mask;
	uint32_t	a_other_mask;
};

#define SYSTEM_RICHACL		"system.richacl"
#define ACL4_XATTR_VERSION	0
#define ACL4_XATTR_MAX_COUNT	1024

#endif  /* __RICHACL_XATTR_H */
