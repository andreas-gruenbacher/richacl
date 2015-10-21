/*
  Copyright (C) 2006, 2008, 2009, 2010  Novell, Inc.
  Copyright (C) 2015  Red Hat, Inc.
  Written by Andreas Gruenbacher <agruenba@redhat.com>

  The getrichacl program is free software; you can redistribute it
  and/or modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2, or (at
  your option) any later version.

  The getrichacl program is distributed in the hope that it will be
  useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * FIXME:
 * Add a way to show only expicitly set acls and hide inherited ones?
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "sys/richacl.h"
#include "string_buffer.h"
#include "common.h"

static const char *progname;

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
		if (richacl_apply_masks(acl, st->st_uid))
			goto fail;
	}
	text = richacl_to_text(*acl, fmt | format_for_mode(st->st_mode));
	if (!text)
		goto fail;
	printf("%s:\n", file);
	puts(text);
	free(text);
	return 0;

fail:
	return -1;
}

static struct option long_options[] = {
	{"access",		2, 0, 'a'},
	{"long",		0, 0, 'l'},
	{"raw",			0, 0,  2 },
	{"full",                0, 0,  3 },
	{"unaligned",		0, 0,  4 },
	{"numeric-ids",		0, 0,  5 },
	{"version",		0, 0, 'v'},
	{"help",		0, 0, 'h'},
	{ NULL,			0, 0,  0 }
};

static void synopsis(int help)
{
	FILE *file = help ? stdout : stderr;

	fprintf(file, "SYNOPSIS: %s [options] file ...\n",
		basename(progname));
	if (!help) {
		fprintf(file, "Try `%s --help' for more information.\n",
			basename(progname));
		exit(1);
	}
	fprintf(file,
"\n"
"Options:\n"
"  --long, -l  Display access masks and flags in their long form.\n"
"  --full      Also show permissions which are always implicitly allowed.\n"
"  --raw       Show acls as stored on the file system including the file masks.\n"
"              Implies --full.\n"
"  --unaligned\n"
"              Do not align acl entries or pad missing permissions with '-'.\n"
"  --numeric-ids\n"
"              Display numeric user and group IDs instead of names.\n"
"  --access[=user[:group:...]}, -a[user[:group:...]}\n"
"              Instead of the acl, show which permissions the caller or a\n"
"              specified user has for file(s).  When a list of groups is\n"
"              given, this overrides the groups the user is in.\n"
"  --version, -v\n"
"              Display the version of %s and exit.\n"
"  --help, -h  This help text.\n"
"\n"
COMMON_HELP,
	basename(progname));
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt_access = 0;
	char *opt_user = NULL;
	int format = RICHACL_TEXT_SIMPLIFY | RICHACL_TEXT_ALIGN;
	uid_t user = -1;
	gid_t *groups = NULL;
	int n_groups = -1;
	int status = 0;
	int c;

	progname = argv[0];

	while ((c = getopt_long(argc, argv, "a::lvh",
				long_options, NULL)) != -1) {
		switch(c) {
			case 'a':  /* --access */
				opt_access = 1;
				opt_user = optarg;
				break;

			case 'l':  /* --long */
				format |= RICHACL_TEXT_LONG;
				break;

			case 2:  /* --raw */
				format |= RICHACL_TEXT_SHOW_MASKS;
				format &= ~RICHACL_TEXT_SIMPLIFY;
				break;

			case 3:  /* --full */
				format &= ~RICHACL_TEXT_SIMPLIFY;
				break;

			case 4:  /* --unaligned */
				format &= ~RICHACL_TEXT_ALIGN;
				break;

			case 5:  /* --numeric-ids */
				format |= RICHACL_TEXT_NUMERIC_IDS;
				break;

			case 'v':
				printf("%s %s\n", basename(progname), VERSION);
				exit(0);

			case 'h':
				synopsis(1);
				break;

			default:
				synopsis(0);
				break;
		}
	}
	if (optind == argc)
		synopsis(0);

	if (opt_user) {
		int n_groups_alloc;
		char *opt_groups;
		struct passwd *passwd = NULL;
		char *endp;

		opt_groups = strchr(opt_user, ':');
		if (opt_groups)
			*opt_groups++ = 0;

		user = strtoul(opt_user, &endp, 10);
		if (*endp) {
			passwd = getpwnam(opt_user);
			if (passwd == NULL) {
				fprintf(stderr, "%s: No such user\n", opt_user);
				exit(1);
			}
			user = passwd->pw_uid;
		} else
			user = -1;

		n_groups_alloc = 32;
		groups = malloc(sizeof(gid_t) * n_groups_alloc);
		if (!groups)
			goto fail;
		if (opt_groups) {
			char *tok;
			n_groups = 0;
			tok = strtok(opt_groups, ":");
			while (tok) {
				struct group *group;

				if (n_groups == n_groups_alloc) {
					gid_t *new_groups;
					n_groups_alloc *= 2;
					new_groups = realloc(groups, sizeof(gid_t) * n_groups_alloc);
					if (!new_groups)
						goto fail;
				}

				groups[n_groups] = strtoul(tok, &endp, 10);
				if (*endp) {
					group = getgrnam(tok);
					if (!group) {
						fprintf(stderr, "%s: No such group\n", tok);
						exit(1);
					}
					groups[n_groups] = group->gr_gid;
				}
				n_groups++;

				tok = strtok(NULL, ":");
			}
		} else {
			if (!passwd)
				passwd = getpwuid(user);
			if (passwd) {
				n_groups = n_groups_alloc;
				if (getgrouplist(passwd->pw_name, passwd->pw_gid,
						 groups, &n_groups) < 0) {
					free(groups);
					groups = malloc(sizeof(gid_t) * n_groups);
					if (getgrouplist(passwd->pw_name, passwd->pw_gid,
							 groups, &n_groups) < 0)
						goto fail;
				}
			} else
				n_groups = 0;
		}
	} else
		user = geteuid();

	for (; optind < argc; optind++) {
		const char *file = argv[optind];
		struct richacl *acl = NULL;
		struct stat st;

		if (stat(file, &st))
			goto fail2;

		if (opt_access) {
			unsigned int mask;
			char *mask_text;

			mask = richacl_access(file, &st, user, groups, n_groups);
			if (mask < 0)
				goto fail2;

			mask_text = richacl_mask_to_text(mask,
					format | format_for_mode(st.st_mode));
			printf("%s  %s\n", mask_text, file);
			free(mask_text);
		} else {
			acl = get_richacl(file, st.st_mode);
			if (!acl) {
				if (!errno)
					goto fail3;
				goto fail2;
			}
			if (print_richacl(file, &acl, &st, format))
				goto fail2;
		}
		richacl_free(acl);
		continue;

	fail2:
		richacl_free(acl);
		perror(file);
	fail3:
		status = 1;
	}

	return status;

fail:
	perror(basename(progname));
	return 1;
}
