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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "sys/richacl.h"
#include "richacl-internal.h"
#include "string_buffer.h"

static void write_acl_flags(struct string_buffer *buffer, unsigned char flags, int align, int fmt)
{
	int cont = 0, i;

	if (!flags)
		return;
	buffer_sprintf(buffer, "%*s:", align, "flags");
	for (i = 0; i < acl_flag_bits_size; i++) {
		if (!(flags & acl_flag_bits[i].a_flag))
			continue;

		flags &= ~acl_flag_bits[i].a_flag;
		if (fmt & RICHACL_TEXT_LONG) {
			if (cont)
				buffer_sprintf(buffer, "/");
			buffer_sprintf(buffer, "%s", acl_flag_bits[i].a_name);
		} else
			buffer_sprintf(buffer, "%c", acl_flag_bits[i].a_char);
		cont = 1;
	}
	if (flags) {
		if (cont)
			buffer_sprintf(buffer, "/");
		buffer_sprintf(buffer, "0x%x", flags);
	}
	buffer_sprintf(buffer, "\n");
}

static void write_type(struct string_buffer *buffer, unsigned short type)
{
	int i;

	for (i = 0; i < type_values_size; i++) {
		if (type == type_values[i].e_type) {
			buffer_sprintf(buffer, "%s", type_values[i].e_name);
			break;
		}
	}
	if (i == type_values_size)
		buffer_sprintf(buffer, "%u", type);
}

static void write_ace_flags(struct string_buffer *buffer, unsigned short flags, int fmt)
{
	int cont = 0, i;

	flags &= ~RICHACE_SPECIAL_WHO;

	for (i = 0; i < ace_flag_bits_size; i++) {
		if (!(flags & ace_flag_bits[i].e_flag))
			continue;

		flags &= ~ace_flag_bits[i].e_flag;
		if (fmt & RICHACL_TEXT_LONG) {
			if (cont)
				buffer_sprintf(buffer, "/");
			buffer_sprintf(buffer, "%s", ace_flag_bits[i].e_name);
		} else
			buffer_sprintf(buffer, "%c", ace_flag_bits[i].e_char);
		cont = 1;
	}
	if (flags) {
		if (cont)
			buffer_sprintf(buffer, "/");
		buffer_sprintf(buffer, "0x%x", flags);
	}
}

void write_mask(struct string_buffer *buffer, unsigned int mask, int fmt)
{
	unsigned int nondir_mask, dir_mask;
	int stuff_written = 0, i;

	/*
	 * In long format, we write the non-directory and/or directory mask
	 * name depending on the context which applies. The short format
	 * does not distinguish between the two, so make sure that we won't
	 * repeat the same mask letters.
	 */
	if (!(fmt & RICHACL_TEXT_LONG)) {
		fmt &= ~RICHACL_TEXT_DIRECTORY_CONTEXT;
		fmt |= RICHACL_TEXT_FILE_CONTEXT;
	} else if (!(fmt & (RICHACL_TEXT_FILE_CONTEXT |
			    RICHACL_TEXT_DIRECTORY_CONTEXT)))
		fmt |= RICHACL_TEXT_FILE_CONTEXT |
		       RICHACL_TEXT_DIRECTORY_CONTEXT;

	nondir_mask = (fmt & RICHACL_TEXT_FILE_CONTEXT) ? mask : 0;
	dir_mask = (fmt & RICHACL_TEXT_DIRECTORY_CONTEXT) ? mask : 0;

	for (i = 0; i < mask_flags_size; i++) {
		int found = 0;

		if ((nondir_mask & mask_flags[i].e_mask) &&
		    (mask_flags[i].e_context & RICHACL_TEXT_FILE_CONTEXT)) {
			nondir_mask &= ~mask_flags[i].e_mask;
			found = 1;
		}
		if ((dir_mask & mask_flags[i].e_mask) &&
		    (mask_flags[i].e_context & RICHACL_TEXT_DIRECTORY_CONTEXT)) {
			dir_mask &= ~mask_flags[i].e_mask;
			found = 1;
		}

		if (fmt & RICHACL_TEXT_SIMPLIFY) {
			/* Hide permissions which are always allowed. */
			if (mask_flags[i].e_mask & RICHACE_POSIX_ALWAYS_ALLOWED)
				continue;
		}

		if (found) {
			if (fmt & RICHACL_TEXT_LONG) {
				if (stuff_written)
					buffer_sprintf(buffer, "/");
				buffer_sprintf(buffer, "%s",
					       mask_flags[i].e_name);
			} else
				buffer_sprintf(buffer, "%c",
					       mask_flags[i].e_char);
			stuff_written = 1;
		} else if (!(fmt & RICHACL_TEXT_LONG) &&
			   (fmt & RICHACL_TEXT_ALIGN) &&
			   (mask_flags[i].e_context & RICHACL_TEXT_FILE_CONTEXT)) {
			buffer_sprintf(buffer, "-");
			stuff_written = 1;
		}
	}
	mask = (nondir_mask | dir_mask);
	if (mask) {
		if (stuff_written)
			buffer_sprintf(buffer, "/");
		buffer_sprintf(buffer, "0x%x", mask);
	}
}

static void write_identifier(struct string_buffer *buffer,
			     const struct richace *ace, int align, int fmt)
{
	/* FIXME: switch to getpwuid_r() and getgrgid_r() here. */

	if (ace->e_flags & RICHACE_SPECIAL_WHO) {
		const char *id = NULL;
		char *dup, *c;
		switch (ace->e_id) {
		case RICHACE_OWNER_SPECIAL_ID:
		    id = richace_owner_who;
		    break;
		case RICHACE_GROUP_SPECIAL_ID:
		    id = richace_group_who;
		    break;
		case RICHACE_EVERYONE_SPECIAL_ID:
		    id = richace_everyone_who;
		    break;
		}

		dup = alloca(strlen(id) + 1);
		strcpy(dup, id);
		for (c = dup; *c; c++)
			*c = tolower(*c);

		buffer_sprintf(buffer, "%*s", align, dup);
	} else if (ace->e_flags & RICHACE_UNMAPPED_WHO) {
		buffer_sprintf(buffer, "%*s", align, ace->e_who);
	} else if (ace->e_flags & RICHACE_IDENTIFIER_GROUP) {
		struct group *group = NULL;

		if (!(fmt & RICHACL_TEXT_NUMERIC_IDS))
			group = getgrgid(ace->e_id);
		if (group)
			buffer_sprintf(buffer, "%*s", align, group->gr_name);
		else
			buffer_sprintf(buffer, "%*d", align, ace->e_id);
	} else {
		struct passwd *passwd = NULL;

		if (!(fmt & RICHACL_TEXT_NUMERIC_IDS))
			passwd = getpwuid(ace->e_id);
		if (passwd)
			buffer_sprintf(buffer, "%*s", align, passwd->pw_name);
		else
			buffer_sprintf(buffer, "%*d", align, ace->e_id);
	}
}

char *richacl_to_text(const struct richacl *acl, int fmt)
{
	struct string_buffer *buffer;
	const struct richace *ace;
	int fmt2, align = 0;
	char *str = NULL;

	if (fmt & RICHACL_TEXT_ALIGN) {
		if (acl->a_flags && align < 6)
			align = 6;
		if ((fmt & RICHACL_TEXT_SHOW_MASKS) && align < 6)
			align = 6;
		richacl_for_each_entry(ace, acl) {
			int a;
			if (richace_is_owner(ace) || richace_is_group(ace))
				a = 6;
			else if (richace_is_everyone(ace))
				a = 9;
			else if (ace->e_flags & RICHACE_UNMAPPED_WHO)
				a = strlen(ace->e_who);
			else if (ace->e_flags & RICHACE_IDENTIFIER_GROUP) {
				struct group *group = NULL;

				if (!(fmt & RICHACL_TEXT_NUMERIC_IDS))
					group = getgrgid(ace->e_id);
				if (group)
					a = strlen(group->gr_name);
				else
					a = snprintf(NULL, 0, "%d", ace->e_id);
			} else {
				struct passwd *passwd = NULL;

				if (!(fmt & RICHACL_TEXT_NUMERIC_IDS))
					passwd = getpwuid(ace->e_id);
				if (passwd)
					a = strlen(passwd->pw_name);
				else
					a = snprintf(NULL, 0, "%d", ace->e_id);
			}
			if (a >= align)
				align = a + 1;
		}
	}

	buffer = alloc_string_buffer(128);
	if (!buffer)
		return NULL;

	write_acl_flags(buffer, acl->a_flags, align, fmt);
	if (fmt & RICHACL_TEXT_SHOW_MASKS) {
		unsigned int allowed = 0;

		fmt2 = fmt;
		richacl_for_each_entry(ace, acl) {
			if (richace_is_inherit_only(ace))
				continue;

			if (richace_is_allow(ace))
				allowed |= ace->e_mask;

			if (ace->e_flags & RICHACE_FILE_INHERIT_ACE)
				fmt2 |= RICHACL_TEXT_FILE_CONTEXT;
			if (ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE)
				fmt2 |= RICHACL_TEXT_DIRECTORY_CONTEXT;
		}

		if (!(fmt & RICHACL_TEXT_SIMPLIFY))
			allowed = ~0;

		buffer_sprintf(buffer, "%*s:", align, "owner");
		write_mask(buffer, acl->a_owner_mask & allowed, fmt2);
		buffer_sprintf(buffer, "::mask\n");
		buffer_sprintf(buffer, "%*s:", align, "group");
		write_mask(buffer, acl->a_group_mask & allowed, fmt2);
		buffer_sprintf(buffer, "::mask\n");
		buffer_sprintf(buffer, "%*s:", align, "other");
		write_mask(buffer, acl->a_other_mask & allowed, fmt2);
		buffer_sprintf(buffer, "::mask\n");
	}

	richacl_for_each_entry(ace, acl) {
		write_identifier(buffer, ace, align, fmt);
		buffer_sprintf(buffer, ":");

		fmt2 = fmt;
		if (ace->e_flags & RICHACE_INHERIT_ONLY_ACE)
			fmt2 &= ~(RICHACL_TEXT_FILE_CONTEXT |
				  RICHACL_TEXT_DIRECTORY_CONTEXT);
		if (ace->e_flags & RICHACE_FILE_INHERIT_ACE)
			fmt2 |= RICHACL_TEXT_FILE_CONTEXT;
		if (ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE)
			fmt2 |= RICHACL_TEXT_DIRECTORY_CONTEXT;

		write_mask(buffer, ace->e_mask, fmt2);
		buffer_sprintf(buffer, ":");
		write_ace_flags(buffer, ace->e_flags, fmt2);
		buffer_sprintf(buffer, ":");
		write_type(buffer, ace->e_type);
		buffer_sprintf(buffer, "\n");
	}

	if (string_buffer_okay(buffer)) {
		str = realloc(buffer->buffer, buffer->offset + 1);
		if (str)
			buffer->buffer = NULL;
	} else
		errno = ENOMEM;
	free_string_buffer(buffer);
	return str;
}
