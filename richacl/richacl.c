/*
  Copyright (C) 2006, 2008, 2009, 2010  Novell, Inc.
  Written by Andreas Gruenbacher <agruen@suse.de>

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this library; if not, write to the Free Software Foundation, Inc.,
  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
 * FIXME: Make ls show a `+' for richacls (in coreutils).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "richacl.h"
#include "string_buffer.h"
#include "user_group.h"

static const char *progname;

void printf_stderr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int modify_richacl(struct richacl **acl2, struct richacl *acl, int acl_has)
{
	struct richace *ace2, *ace;

	richacl_for_each_entry(ace, acl) {
		struct richacl *acl3;
		struct richace *ace3;

		richacl_for_each_entry(ace2, *acl2) {
			if (ace2->e_type == ace->e_type &&
			    richace_is_same_identifier(ace, ace2)) {
				ace2->e_mask = ace->e_mask;
				ace2->e_flags = ace->e_flags;
				break;
			}
		}
		if (ace2 != (*acl2)->a_entries + (*acl2)->a_count)
			continue;

		acl3 = richacl_alloc((*acl2)->a_count + 1);
		if (!acl3)
			return -1;
		ace3 = acl3->a_entries;
		if (richace_is_deny(ace)) {
			richacl_for_each_entry(ace2, *acl2) {
				if (!richace_is_deny(ace2))
					break;
				richace_copy(ace3++, ace2);
			}
			richace_copy(ace3++, ace);
			while (ace2 != (*acl2)->a_entries + (*acl2)->a_count)
				richace_copy(ace3++, ace2++);
		} else {
			richacl_for_each_entry(ace2, *acl2)
				richace_copy(ace3++, ace2);
			richace_copy(ace3++, ace);
		}

		richacl_free(*acl2);
		*acl2 = acl3;
	}

	if (acl_has & RICHACL_TEXT_FLAGS)
		(*acl2)->a_flags = acl->a_flags;

	if (!((acl_has & RICHACL_TEXT_OWNER_MASK) && 
	      (acl_has & RICHACL_TEXT_GROUP_MASK) && 
	      (acl_has & RICHACL_TEXT_OTHER_MASK)))
		richacl_compute_max_masks(*acl2);
	if (acl_has & RICHACL_TEXT_OWNER_MASK)
		(*acl2)->a_owner_mask = acl->a_owner_mask;
	if (acl_has & RICHACL_TEXT_GROUP_MASK)
		(*acl2)->a_group_mask = acl->a_group_mask;
	if (acl_has & RICHACL_TEXT_OTHER_MASK)
		(*acl2)->a_other_mask = acl->a_other_mask;

	return 0;
}

static struct richacl *get_richacl(const char *file, mode_t mode)
{
	struct richacl *acl;

	acl = richacl_get_file(file);
	if (!acl && (errno == ENODATA || errno == ENOTSUP || errno == ENOSYS)) {
		acl = richacl_from_mode(mode);
	}
	return acl;
}

static const char *flagstr(mode_t mode)
{
	static char str[4];

	str[0] = (mode & S_ISUID) ? 's' : '-';
	str[1] = (mode & S_ISGID) ? 's' : '-';
	str[2] = (mode & S_ISVTX) ? 't' : '-';
	str[3] = '\0';
	return str;
}

int format_for_mode(mode_t mode)
{
	if (S_ISDIR(mode))
		return RICHACL_TEXT_DIRECTORY_CONTEXT;
	else
		return RICHACL_TEXT_FILE_CONTEXT;
}

static int print_richacl(const char *file, struct richacl **acl,
			 struct stat *st, int fmt)
{
	char *text;

	if (!(fmt & RICHACL_TEXT_SHOW_MASKS)) {
		if (richacl_apply_masks(acl))
			goto fail;
	}
	text = richacl_to_text(*acl, fmt | format_for_mode(st->st_mode));
	if (!text)
		goto fail;
	printf("# file: %s\n# owner: %s\n# group: %s\n",
	       file,
	       user_name(st->st_uid, 0),
	       group_name(st->st_gid, 0));
	if ((st->st_mode & (S_ISVTX | S_ISUID | S_ISGID)))
		printf("# flags: %s\n", flagstr(st->st_mode));

	puts(text);
	free(text);
	return 0;

fail:
	return -1;
}

void remove_comments(struct string_buffer *buffer)
{
	char *c = NULL, *d = buffer->buffer;

	for (;;) {
		if (c && (*d == '\n' || *d == 0)) {
			size_t sz = buffer->buffer + buffer->offset - d;
			memmove(c, d, sz + 1);
			buffer->offset -= d - c;
			d = c;
			c = NULL;
		} else if (*d == 0)
			break;
		else if (*d == '#') {
			if (!c && (d == buffer->buffer || isspace(d[-1]))) {
				c = d;
				while (c != buffer->buffer &&
				       *c != '\n' && isspace(*c))
					c--;
			}
		}
		d++;
	}
}

static struct option long_options[] = {
	{"access",		2, 0,  3 },
	{"get",			0, 0, 'g'},
	{"modify",		1, 0, 'm'},
	{"modify-file",		1, 0, 'M'},
	{"set",			1, 0, 's'},
	{"set-file",		1, 0, 'S'},
	{"remove",		0, 0, 'r'},
	{"long",		0, 0, 'l'},
	{"raw",			0, 0,  1 },
	{"dry-run",		0, 0,  2 },
	{"version",		0, 0, 'v'},
	{"help",		0, 0, 'h'},
	{ NULL,			0, 0,  0 }
};

static void synopsis(int help)
{
	FILE *file = help ? stdout : stderr;

	fprintf(file, "SYNOPSIS: %s [options] {command} file ...\n",
		basename(progname));
	if (!help)
		exit(1);
	fprintf(file,
"\n"
"Commands:\n"
"  --get       Display the ACL of file(s). Multiple ACL entries are separated\n"
"              by newline.\n"
"  --modify acl_entries\n"
"              Modify the ACL of file(s) by replacing existing entries with\n"
"              the entries in acl_entries, and adding all new entries.\n"
"  --set acl   Set the ACL of file(s) to acl. Multiple ACL entries are\n"
"              separated by whitespace or commas.\n"
"  --modify-file acl_entries_file, --set-file acl_file\n"
"              Identical to --modify / --set, but read the ACL from a file\n"
"              instead. If the file is `-', read from standard input.\n"
"  --set-file acl_file\n"
"              Identical to --set, but read the ACL from a file\n"
"              instead. If the file is `-', read from standard input.\n"
"  --remove    Delete the ACL of file(s).\n"
"  --access[=user[:group:...]}\n"
"              Show which permissions the caller or a specified user has for\n"
"              file(s).  When a list of groups is given, this overrides the\n"
"              groups the user is in.\n"
"              capabilities. \n"
"  --version   Display the version of %s and exit.\n"
"  --help      This help text.\n"
"\n"
"Options:\n"
"  --long      Display access masks and flags in their long form.\n"
"\n"
"ACL entries are represented by colon separated <who>:<mask>:<flags>:<type>\n"
"fields. The <who> field may be \"owner@\", \"group@\", \"everyone@\", a user\n"
"name or ID, or a group name or ID. Groups must have the identifier_group(g)\n"
"flag set in the <flags> field. The <type> field may be \"allow\" or \"deny\".\n"
"The <mask> and <flags> fields are lists of single-letter abbreviations or\n"
"slash-separated names, or a combination of both.\n"
"\n"
"The supported <mask> values are:\n"
"\tread_data (r), list_directory (r), write_data (w), add_file (w),\n"
"\tappend_data (a), add_subdirectory (a), read_named_attrs (N),\n"
"\twrite_named_attrs (n), execute (x), delete_child (d),\n"
"\tread_attributes (T), write_attributes (t), delete (D),\n"
"\tread_acl (M), write_acl (m), take_ownership (o), synchronize (s)\n"
"\n"
"The supported <flags> values are:\n"
"\tfile_inherit_ace (f), directory_inherit_ace (d),\n"
"\tno_propagate_inherit_ace (n), inherit_only_ace (i),\n"
"\tidentifier_group (g), inherited_ace (a)\n"
"\n"
"Per-ACL flag values are:\n"
"\tauto_inherit (a), protected (p), defaulted (d), posix_mapped (P)\n",
	basename(progname));
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt_get = 0, opt_remove = 0, opt_access = 0, opt_dry_run = 0;
	int opt_modify = 0, opt_set = 0;
	char *opt_user = NULL;
	char *acl_text = NULL, *acl_file = NULL;
	int format = RICHACL_TEXT_SIMPLIFY | RICHACL_TEXT_ALIGN;
	uid_t user = -1;
	gid_t *groups = NULL;
	int n_groups = -1;
	int status = 0;
	int c;

	struct richacl *acl = NULL;
	int acl_has;

	progname = argv[0];

	while ((c = getopt_long(argc, argv, "gm:M:s:S:nrlnvh",
				long_options, NULL)) != -1) {
		switch(c) {
			case 'g':
				opt_get = 1;
				break;
			case 'm':
				opt_modify = 1;
				acl_text = optarg;
				break;

			case 'M':
				opt_modify = 1;
				acl_file = optarg;
				break;
			case 's':
				opt_set = 1;
				acl_text = optarg;
				break;

			case 'S':
				opt_set = 1;
				acl_file = optarg;
				break;

			case 'r':
				opt_remove = 1;
				break;

			case 'l':
				format |= RICHACL_TEXT_LONG;
				break;

			case 'v':
				printf("%s %s\n", basename(progname), VERSION);
				exit(0);

			case 'h':
				synopsis(1);
				break;

			case 1:  /* --raw */
				format |= RICHACL_TEXT_SHOW_MASKS;
				format &= ~RICHACL_TEXT_SIMPLIFY;
				break;

			case 2:  /* --dry-run */
				opt_dry_run = 1;
				break;

			case 3:  /* --access */
				opt_access = 1;
				opt_user = optarg;
				break;

			default:
				synopsis(0);
				break;
		}
	}
	if (opt_get + opt_remove + opt_modify + opt_set + opt_access != 1 ||
	    (acl_text ? 1 : 0) + (acl_file ? 1 : 0) > 1 ||
	    optind == argc)
		synopsis(argc == 1);

	if (acl_text) {
		acl = richacl_from_text(acl_text, &acl_has, printf_stderr);
		if (!acl)
			return 1;
	}

	if (acl_file) {
		struct string_buffer *buffer;
		char buf[4097];
		FILE *file = stdin;
		ssize_t sz;

		buffer = alloc_string_buffer(1024);
		if (!buffer) {
			perror("");
			return 1;
		}

		if (strcmp(acl_file, "-")) {
			file = fopen(acl_file, "r");
			if (!file) {
				perror(acl_file);
				return 1;
			}
		}
		do {
			sz = fread(buf, 1, sizeof(buf) - 1, file);
			buf[sz] = 0;
			buffer_sprintf(buffer, "%s", buf);
		} while (!(feof(file) || ferror(file)));
		fclose(file);
		if (ferror(file)) {
			perror(acl_file);
			return 1;
		}

		remove_comments(buffer);
		acl = richacl_from_text(buffer->buffer, &acl_has, printf_stderr);
		if (!acl)
			return 1;
		free_string_buffer(buffer);
	}

	/* Compute all masks which haven't been set explicitly. */
	if (opt_set && acl && !((acl_has & RICHACL_TEXT_OWNER_MASK) &&
				(acl_has & RICHACL_TEXT_GROUP_MASK) &&
				(acl_has & RICHACL_TEXT_OTHER_MASK))) {
		unsigned int owner_mask = acl->a_owner_mask;
		unsigned int group_mask = acl->a_group_mask;
		unsigned int other_mask = acl->a_other_mask;

		richacl_compute_max_masks(acl);
		if (acl_has & RICHACL_TEXT_OWNER_MASK)
			acl->a_owner_mask = owner_mask;
		if (acl_has & RICHACL_TEXT_GROUP_MASK)
			acl->a_group_mask = group_mask;
		if (acl_has & RICHACL_TEXT_OTHER_MASK)
			acl->a_other_mask = other_mask;
	}

	if (opt_user) {
		char *opt_groups;
		struct passwd *passwd;

		opt_groups = strchr(opt_user, ':');
		if (opt_groups)
			*opt_groups++ = 0;

		passwd = getpwnam(opt_user);
		if (passwd == NULL) {
			fprintf(stderr, "%s: No such user\n", opt_user);
			exit(1);
		}
		user = passwd->pw_uid;

		n_groups = 32;
		groups = malloc(sizeof(gid_t) * n_groups);
		if (!groups)
			goto fail;
		if (opt_groups) {
			int avail = n_groups;
			char *tok;
			n_groups = 0;
			tok = strtok(opt_groups, ":");
			while (tok) {
				struct group *group;

				if (n_groups == avail) {
					gid_t *new_groups;
					avail *= 2;
					new_groups = realloc(groups, sizeof(gid_t) * avail);
					if (!new_groups)
						goto fail;
				}
				group = getgrnam(tok);
				if (!group) {
					fprintf(stderr, "%s: No such group\n", tok);
					exit(1);
				}
				groups[n_groups++] = group->gr_gid;

				tok = strtok(NULL, ":");
			}
		} else {
			if (getgrouplist(opt_user, passwd->pw_gid, groups, &n_groups) < 0) {
				free(groups);
				groups = malloc(sizeof(gid_t) * n_groups);
				if (getgrouplist(opt_user, passwd->pw_gid, groups, &n_groups) < 0)
					goto fail;
			}
		}
	}

	for (; optind < argc; optind++) {
		const char *file = argv[optind];
		struct richacl *acl2 = NULL;
		struct stat st;

		if (opt_get || opt_modify || opt_access || opt_dry_run)
			if (stat(file, &st))
				goto fail;

		if (opt_set) {
			if (opt_dry_run) {
				if (print_richacl(file, &acl, &st, format))
					goto fail;
			}
			if (richacl_set_file(file, acl))
				goto fail;
		} else if (opt_modify) {
			acl2 = get_richacl(file, st.st_mode);
			if (!acl2)
				goto fail;
			if (modify_richacl(&acl2, acl, acl_has))
				goto fail;
			if (opt_dry_run) {
				if (print_richacl(file, &acl2, &st, format))
					goto fail;
			} else {
				if (richacl_set_file(file, acl2))
					goto fail;
			}
		} else if (opt_remove) {
			if (removexattr(file, "system.richacl")) {
				if (errno != ENODATA)
					goto fail;
			}
		} else if (opt_access) {
			unsigned int mask;
			char *mask_text;

			if (stat(file, &st) != 0)
				goto fail;
			mask = richacl_access(file, &st, user, groups, n_groups);
			if (mask < 0)
				goto fail;

			mask_text = richacl_mask_to_text(mask,
					format | format_for_mode(st.st_mode));
			printf("%s  %s\n", mask_text, file);
			free(mask_text);
		} else {
			acl2 = get_richacl(file, st.st_mode);
			if (!acl2)
				goto fail;
			if (print_richacl(file, &acl2, &st, format))
				goto fail;
		}
		richacl_free(acl2);
		continue;

	fail:
		richacl_free(acl2);
		perror(file);
		status = 1;
	}

	richacl_free(acl);
	return status;
}
