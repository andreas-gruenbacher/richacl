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

#ifndef __UAPI_RICHACL_H
#define __UAPI_RICHACL_H

/* a_flags values */
#define RICHACL_AUTO_INHERIT			0x01
#define RICHACL_PROTECTED			0x02
#define RICHACL_DEFAULTED			0x04
#define RICHACL_WRITE_THROUGH			0x40
#define RICHACL_MASKED				0x80

/* e_type values */
#define RICHACE_ACCESS_ALLOWED_ACE_TYPE		0x0000
#define RICHACE_ACCESS_DENIED_ACE_TYPE		0x0001

/* e_flags bitflags */
#define RICHACE_FILE_INHERIT_ACE		0x0001
#define RICHACE_DIRECTORY_INHERIT_ACE		0x0002
#define RICHACE_NO_PROPAGATE_INHERIT_ACE	0x0004
#define RICHACE_INHERIT_ONLY_ACE		0x0008
#define RICHACE_IDENTIFIER_GROUP		0x0040
#define RICHACE_INHERITED_ACE			0x0080
#define RICHACE_UNMAPPED_WHO			0x2000
#define RICHACE_SPECIAL_WHO			0x4000

/* e_mask bitflags */
#define RICHACE_READ_DATA			0x00000001
#define RICHACE_LIST_DIRECTORY			0x00000001
#define RICHACE_WRITE_DATA			0x00000002
#define RICHACE_ADD_FILE			0x00000002
#define RICHACE_APPEND_DATA			0x00000004
#define RICHACE_ADD_SUBDIRECTORY		0x00000004
#define RICHACE_READ_NAMED_ATTRS		0x00000008
#define RICHACE_WRITE_NAMED_ATTRS		0x00000010
#define RICHACE_EXECUTE				0x00000020
#define RICHACE_DELETE_CHILD			0x00000040
#define RICHACE_READ_ATTRIBUTES			0x00000080
#define RICHACE_WRITE_ATTRIBUTES		0x00000100
#define RICHACE_WRITE_RETENTION			0x00000200
#define RICHACE_WRITE_RETENTION_HOLD		0x00000400
#define RICHACE_DELETE				0x00010000
#define RICHACE_READ_ACL			0x00020000
#define RICHACE_WRITE_ACL			0x00040000
#define RICHACE_WRITE_OWNER			0x00080000
#define RICHACE_SYNCHRONIZE			0x00100000

/* e_id values */
#define RICHACE_OWNER_SPECIAL_ID		0
#define RICHACE_GROUP_SPECIAL_ID		1
#define RICHACE_EVERYONE_SPECIAL_ID		2

#define RICHACL_VALID_FLAGS (					\
	RICHACL_AUTO_INHERIT |					\
	RICHACL_PROTECTED |					\
	RICHACL_DEFAULTED |					\
	RICHACL_WRITE_THROUGH |					\
	RICHACL_MASKED )

#define RICHACE_VALID_FLAGS (					\
	RICHACE_FILE_INHERIT_ACE |				\
	RICHACE_DIRECTORY_INHERIT_ACE |				\
	RICHACE_NO_PROPAGATE_INHERIT_ACE |			\
	RICHACE_INHERIT_ONLY_ACE |				\
	RICHACE_IDENTIFIER_GROUP |				\
	RICHACE_INHERITED_ACE |					\
	RICHACE_UNMAPPED_WHO |					\
	RICHACE_SPECIAL_WHO )

#define RICHACE_INHERITANCE_FLAGS (				\
	RICHACE_FILE_INHERIT_ACE |				\
	RICHACE_DIRECTORY_INHERIT_ACE |				\
	RICHACE_NO_PROPAGATE_INHERIT_ACE |			\
	RICHACE_INHERIT_ONLY_ACE |				\
	RICHACE_INHERITED_ACE )

/* Valid RICHACE_* flags for directories and non-directories */
#define RICHACE_VALID_MASK (					\
	RICHACE_READ_DATA | RICHACE_LIST_DIRECTORY |		\
	RICHACE_WRITE_DATA | RICHACE_ADD_FILE |			\
	RICHACE_APPEND_DATA | RICHACE_ADD_SUBDIRECTORY |	\
	RICHACE_READ_NAMED_ATTRS |				\
	RICHACE_WRITE_NAMED_ATTRS |				\
	RICHACE_EXECUTE |					\
	RICHACE_DELETE_CHILD |					\
	RICHACE_READ_ATTRIBUTES |				\
	RICHACE_WRITE_ATTRIBUTES |				\
	RICHACE_WRITE_RETENTION |				\
	RICHACE_WRITE_RETENTION_HOLD |				\
	RICHACE_DELETE |					\
	RICHACE_READ_ACL |					\
	RICHACE_WRITE_ACL |					\
	RICHACE_WRITE_OWNER |					\
	RICHACE_SYNCHRONIZE )

/*
 * The POSIX permissions are supersets of the following richacl permissions:
 *
 *  - MAY_READ maps to READ_DATA or LIST_DIRECTORY, depending on the type
 *    of the file system object.
 *
 *  - MAY_WRITE maps to WRITE_DATA or RICHACE_APPEND_DATA for files, and to
 *    ADD_FILE, RICHACE_ADD_SUBDIRECTORY, or RICHACE_DELETE_CHILD for directories.
 *
 *  - MAY_EXECUTE maps to RICHACE_EXECUTE.
 *
 *  (Some of these richacl permissions have the same bit values.)
 */
#define RICHACE_POSIX_MODE_READ (			\
		RICHACE_READ_DATA |			\
		RICHACE_LIST_DIRECTORY)
#define RICHACE_POSIX_MODE_WRITE (			\
		RICHACE_WRITE_DATA |			\
		RICHACE_ADD_FILE |			\
		RICHACE_APPEND_DATA |			\
		RICHACE_ADD_SUBDIRECTORY |		\
		RICHACE_DELETE_CHILD)
#define RICHACE_POSIX_MODE_EXEC RICHACE_EXECUTE
#define RICHACE_POSIX_MODE_ALL (			\
		RICHACE_POSIX_MODE_READ |		\
		RICHACE_POSIX_MODE_WRITE |		\
		RICHACE_POSIX_MODE_EXEC)

/*
 * These permissions are always allowed no matter what the acl says.
 */
#define RICHACE_POSIX_ALWAYS_ALLOWED (			\
		RICHACE_SYNCHRONIZE |			\
		RICHACE_READ_ATTRIBUTES |		\
		RICHACE_READ_ACL)

/*
 * The owner is implicitly granted these permissions under POSIX.
 */
#define RICHACE_POSIX_OWNER_ALLOWED (			\
		RICHACE_WRITE_ATTRIBUTES |		\
		RICHACE_WRITE_OWNER |			\
		RICHACE_WRITE_ACL)

#endif /* __UAPI_RICHACL_H */
