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

static inline bool
ace_inherits_to_directory(const struct richace *ace)
{
	if (ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE)
		return true;
	if ((ace->e_flags & RICHACE_FILE_INHERIT_ACE) &&
	    !(ace->e_flags & RICHACE_NO_PROPAGATE_INHERIT_ACE))
		return true;
	return false;
}

/**
 * richacl_inherit  -  compute the inheritable acl
 * @dir_acl:	acl of the containing direcory
 * @isdir:	inherit by a directory or non-directory?
 *
 * A directory can have acl entries which files and/or directories created
 * inside the directory will inherit.  This function computes the acl for such
 * a new file.  If there is no inheritable acl, it will return an empty acl.
 */
struct richacl *
richacl_inherit(const struct richacl *dir_acl, int isdir)
{
	const struct richace *dir_ace;
	struct richacl *acl = NULL;
	struct richace *ace;
	int count = 0;

	if (isdir) {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!ace_inherits_to_directory(dir_ace))
				continue;

			count++;
		}
		acl = richacl_alloc(count);
		if (!acl)
			return NULL;
		ace = acl->a_entries;
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!ace_inherits_to_directory(dir_ace))
				continue;

			if (richace_copy(ace, dir_ace))
				goto fail;
			if (dir_ace->e_flags & RICHACE_NO_PROPAGATE_INHERIT_ACE)
				ace->e_flags &= ~RICHACE_INHERITANCE_FLAGS;
			else if (dir_ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE)
				ace->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
			else
				ace->e_flags |= RICHACE_INHERIT_ONLY_ACE;
			ace++;
		}
	} else {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & RICHACE_FILE_INHERIT_ACE))
				continue;
			count++;
		}
		acl = richacl_alloc(count);
		if (!acl)
			return NULL;
		ace = acl->a_entries;
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & RICHACE_FILE_INHERIT_ACE))
				continue;
			if (richace_copy(ace, dir_ace))
				goto fail;
			ace->e_flags &= ~RICHACE_INHERITANCE_FLAGS;
			/*
			 * RICHACE_DELETE_CHILD is meaningless for
			 * non-directories, so clear it.
			 */
			ace->e_mask &= ~RICHACE_DELETE_CHILD;
			ace++;
		}
	}

	if (richacl_is_auto_inherit(dir_acl)) {
		acl->a_flags = RICHACL_AUTO_INHERIT;
		richacl_for_each_entry(ace, acl)
			ace->e_flags |= RICHACE_INHERITED_ACE;
	} else {
		richacl_for_each_entry(ace, acl)
			ace->e_flags &= ~RICHACE_INHERITED_ACE;
	}

	return acl;

fail:
	richacl_free(acl);
	return NULL;
}
