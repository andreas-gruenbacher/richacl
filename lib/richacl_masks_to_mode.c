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
#include "richacl-internal.h"

/**
 * richacl_masks_to_mode  -  compute the file permission bits from the file masks
 *
 * When the file permission bits of a file are set with chmod(), this specifies
 * the maximum permissions that processes will get.  All permissions beyond
 * that are removed from the file masks, and become ineffective.
 *
 * Conversely, when setting a richacl, we set the file permission bits to
 * indicate maximum permissions: for example, we set the Write permission when
 * a mask contains RICHACE_APPEND_DATA even if it does not also contain
 * RICHACE_WRITE_DATA.
 *
 * Permissions which are not in RICHACE_POSIX_MODE_READ, RICHACE_POSIX_MODE_WRITE, or
 * RICHACE_POSIX_MODE_EXEC cannot be represented in the file permission bits.
 * Those permissions can still be effective, but only if the masks were set
 * explicitly (for example, by setting the richacl xattr), and not for new
 * files or after a chmod().
 */
int
richacl_masks_to_mode(const struct richacl *acl)
{
	return richacl_mask_to_mode(acl->a_owner_mask) << 6 |
	       richacl_mask_to_mode(acl->a_group_mask) << 3 |
	       richacl_mask_to_mode(acl->a_other_mask);
}
