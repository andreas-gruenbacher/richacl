/*
  Copyright (C) 2006, 2009, 2010  Novell, Inc.
  Copyright (C) 2015, 2016  Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "sys/richacl.h"
#include "richacl-internal.h"

/*
 * richacl_inherit_inode  -  compute inherited acl and file mode
 * @dir_acl:	acl of the containing directory
 * @mode_p:	mode of the new inode
 * @umask:	function returning the current umask
 * @umask_arg:	argument to umask()
 *
 * The file permission bits in @mode_p must be set to the create mode by the
 * caller.
 *
 * If there is an inheritable acl, the maximum permissions that the acl grants
 * are computed and the file masks of the new acl are set accordingly.
 */
struct richacl *
richacl_inherit_inode(const struct richacl *dir_acl, mode_t *mode_p,
		      mode_t (*umask)(void *), void *umask_arg)
{
	struct richacl *acl;
	mode_t mode = *mode_p;

	acl = richacl_inherit(dir_acl, S_ISDIR(mode));
	if (acl) {
		if (richacl_equiv_mode(acl, &mode) == 0) {
			*mode_p &= mode;
			richacl_free(acl);
			acl = NULL;
		} else {
			/*
			 * We need to set RICHACL_PROTECTED because we are
			 * doing an implicit chmod
			 */
			if (richacl_is_auto_inherit(acl))
				acl->a_flags |= RICHACL_PROTECTED;

			richacl_compute_max_masks(acl);
			/*
			 * Ensure that the acl will not grant any permissions
			 * beyond the create mode.
			 */
			acl->a_flags |= RICHACL_MASKED;
			acl->a_owner_mask &=
				richacl_mode_to_mask(mode >> 6);
			acl->a_group_mask &=
				richacl_mode_to_mask(mode >> 3);
			acl->a_other_mask &=
				richacl_mode_to_mask(mode);
		}
	} else
		*mode_p &= ~umask(umask_arg);

	return acl;
}
