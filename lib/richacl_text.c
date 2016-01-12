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
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include "sys/richacl.h"
#include "richacl-internal.h"
#include "string_buffer.h"

const struct richacl_flag_bit acl_flag_bits[] = {
	{ 'm', RICHACL_MASKED, "masked" },
	{ 'w', RICHACL_WRITE_THROUGH, "write_through" },
	{ 'a', RICHACL_AUTO_INHERIT, "auto_inherit" },
	{ 'p', RICHACL_PROTECTED, "protected" },
	{ 'd', RICHACL_DEFAULTED, "defaulted" },
};
const unsigned int acl_flag_bits_size = ARRAY_SIZE(acl_flag_bits);

const struct richacl_type_value type_values[] = {
	{ RICHACE_ACCESS_ALLOWED_ACE_TYPE, "allow" },
	{ RICHACE_ACCESS_DENIED_ACE_TYPE,  "deny" },
};
const unsigned int type_values_size = ARRAY_SIZE(type_values);

#define FLAGS_BIT(c, name, str) \
	{ RICHACE_ ## name, c, str }

const struct richace_flag_bit ace_flag_bits[] = {
	FLAGS_BIT('f', FILE_INHERIT_ACE, "file_inherit"),
	FLAGS_BIT('d', DIRECTORY_INHERIT_ACE, "dir_inherit"),
	FLAGS_BIT('n', NO_PROPAGATE_INHERIT_ACE, "no_propagate"),
	FLAGS_BIT('i', INHERIT_ONLY_ACE, "inherit_only"),
	FLAGS_BIT('a', INHERITED_ACE, "inherited"),
	FLAGS_BIT('u', UNMAPPED_WHO, "unmapped"),
};
const unsigned int ace_flag_bits_size = ARRAY_SIZE(ace_flag_bits);

#undef FLAGS_BIT

#define MASK_BIT(c, name, str) \
	{ RICHACE_ ## name, c, str, RICHACL_TEXT_FILE_CONTEXT | \
				 RICHACL_TEXT_DIRECTORY_CONTEXT }
#define FILE_MASK_BIT(c, name, str) \
	{ RICHACE_ ## name, c, str, RICHACL_TEXT_FILE_CONTEXT }
#define DIRECTORY_MASK_BIT(c, name, str) \
	{ RICHACE_ ## name, c, str, RICHACL_TEXT_DIRECTORY_CONTEXT }

const struct richacl_mask_flag mask_flags[] = {
	FILE_MASK_BIT('r', READ_DATA, "read_data"),
	DIRECTORY_MASK_BIT('r', LIST_DIRECTORY, "list_directory"),
	FILE_MASK_BIT('w', WRITE_DATA, "write_data"),
	DIRECTORY_MASK_BIT('w', ADD_FILE, "add_file"),
	FILE_MASK_BIT('p', APPEND_DATA, "append_data"),
	DIRECTORY_MASK_BIT('p', ADD_SUBDIRECTORY, "add_subdirectory"),
	MASK_BIT('x', EXECUTE, "execute"),
	/* DELETE_CHILD is only meaningful for directories but it might also
	   be set in an ACE of a file, so print it in file context as well.  */
	MASK_BIT('d', DELETE_CHILD, "delete_child"),
	MASK_BIT('D', DELETE, "delete"),
	MASK_BIT('a', READ_ATTRIBUTES, "read_attributes"),
	MASK_BIT('A', WRITE_ATTRIBUTES, "write_attributes"),
	MASK_BIT('R', READ_NAMED_ATTRS, "read_named_attrs"),
	MASK_BIT('W', WRITE_NAMED_ATTRS, "write_named_attrs"),
	MASK_BIT('c', READ_ACL, "read_acl"),
	MASK_BIT('C', WRITE_ACL, "write_acl"),
	MASK_BIT('o', WRITE_OWNER, "write_owner"),
	MASK_BIT('S', SYNCHRONIZE, "synchronize"),
	MASK_BIT('e', WRITE_RETENTION, "write_retention"),
	MASK_BIT('E', WRITE_RETENTION_HOLD, "write_retention_hold"),
};
const unsigned int mask_flags_size = ARRAY_SIZE(mask_flags);

#undef MASK_BIT
#undef FILE_MASK_BIT
#undef DIRECTORY_MASK_BIT

/**
 * Windows also defines the following sets of permissions:
 *
 * Read:
 * 	ACE4_READ_DATA | ACE4_LIST_DIRECTORY |
 * 	ACE4_READ_ATTRIBUTES |
 * 	ACE4_READ_NAMED_ATTRS |
 * 	ACE4_READ_ACL |
 * 	ACE4_SYNCHRONIZE
 *
 * Write:
 *	ACE4_WRITE_DATA | ACE4_ADD_FILE |
 *	ACE4_APPEND_DATA | ACE4_ADD_SUBDIRECTORY |
 *	ACE4_WRITE_ATTRIBUTES |
 *	ACE4_WRITE_NAMED_ATTRS |
 *	ACE4_READ_ACL |
 *	ACE4_SYNCHRONIZE
 *
 * Read & Execute (Files) / List Folder Contents (Directories):
 * 	ACE4_EXECUTE |
 * 	ACE4_READ_DATA | ACE4_LIST_DIRECTORY |
 * 	ACE4_READ_ATTRIBUTES |
 * 	ACE4_READ_NAMED_ATTRS |
 * 	ACE4_READ_ACL |
 * 	ACE4_SYNCHRONIZE
 *
 * Modify:
 * 	ACE4_EXECUTE |
 * 	ACE4_READ_DATA | ACE4_LIST_DIRECTORY |
 * 	ACE4_READ_ATTRIBUTES |
 * 	ACE4_READ_NAMED_ATTRS |
 * 	ACE4_WRITE_DATA | ACE4_ADD_FILE |
 * 	ACE4_APPEND_DATA | ACE4_ADD_SUBDIRECTORY |
 * 	ACE4_WRITE_ATTRIBUTES |
 * 	ACE4_WRITE_NAMED_ATTRS |
 * 	ACE4_DELETE |
 * 	ACE4_READ_ACL |
 * 	ACE4_SYNCHRONIZE
 *
 * Full Control:
 * 	ACE4_EXECUTE |
 * 	ACE4_READ_DATA | ACE4_LIST_DIRECTORY |
 * 	ACE4_READ_ATTRIBUTES |
 * 	ACE4_READ_NAMED_ATTRS |
 * 	ACE4_WRITE_DATA | ACE4_ADD_FILE |
 * 	ACE4_APPEND_DATA | ACE4_ADD_SUBDIRECTORY |
 * 	ACE4_WRITE_ATTRIBUTES |
 * 	ACE4_WRITE_NAMED_ATTRS |
 * 	ACE4_DELETE_CHILD |
 * 	ACE4_DELETE |
 * 	ACE4_READ_ACL |
 * 	ACE4_WRITE_ACL |
 *	ACE4_WRITE_OWNER |
 * 	ACE4_SYNCHRONIZE
 *
 * Reference: http://support.microsoft.com/en-us/kb/308419
 *
 * The ACE4_WRITE_RETENTION and ACE4_WRITE_RETENTION_HOLD permissions are not
 * defined in Windows, and are not included in these sets.
 *
 * Solaris has similar but not identical sets:
 *   read_set, write_set, modify_set, full_set.
 */
