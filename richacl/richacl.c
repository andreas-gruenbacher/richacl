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
 * FIXME:
 * Make ls show a `+' for richacls (in coreutils).
 * Add a way to show only expicitly set acls, and hide inherited ones.
 * Convert a non-Automatic-Inheritance tree into an Automatic Inheritance one?
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

#include "richacl.h"
#include "string_buffer.h"

static const char *progname;
int opt_repropagate;

void printf_stderr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#define richacl_for_each_entry_continue(_ace, _acl) \
	for ((_ace)++; \
	     (_ace) != (_acl)->a_entries + (_acl)->a_count; \
	     (_ace)++)

static inline int richace_is_inherited(const struct richace *ace)
{
	return ace->e_flags & ACE4_INHERITED_ACE;
}

static void add_implicitly_granted_permissions(struct richacl *acl)
{
	struct richace *ace;

	richacl_for_each_entry(ace, acl) {
		if (richace_is_allow(ace)) {
			ace->e_mask |= ACE4_POSIX_ALWAYS_ALLOWED;
			if (richace_is_owner(ace))
				ace->e_mask |= ACE4_POSIX_OWNER_ALLOWED;
		} else if (richace_is_deny(ace)) {
			ace->e_mask &= ~ACE4_POSIX_ALWAYS_ALLOWED;
			if (richace_is_owner(ace))
				ace->e_mask &= ~ACE4_POSIX_OWNER_ALLOWED;
		}
	}
}

static void compute_masks(struct richacl *acl, int acl_has)
{
	unsigned int owner_mask = acl->a_owner_mask;
	unsigned int group_mask = acl->a_group_mask;
	unsigned int other_mask = acl->a_other_mask;

	if ((acl_has & RICHACL_TEXT_OWNER_MASK) &&
	    (acl_has & RICHACL_TEXT_GROUP_MASK) &&
	    (acl_has & RICHACL_TEXT_OTHER_MASK) &&
	    (acl_has & RICHACL_TEXT_FLAGS))
		return;

	if (!(acl_has & RICHACL_TEXT_FLAGS))
		acl->a_flags &= ~ACL4_MASKED;
	richacl_compute_max_masks(acl);
	if (acl_has & RICHACL_TEXT_OWNER_MASK) {
		if (!(acl_has & RICHACL_TEXT_FLAGS) &&
		    (acl->a_owner_mask & ~owner_mask))
			acl->a_flags |= ACL4_MASKED;
		acl->a_owner_mask = owner_mask;
	}
	if (acl_has & RICHACL_TEXT_GROUP_MASK) {
		if (!(acl_has & RICHACL_TEXT_FLAGS) &&
		    (acl->a_group_mask & ~group_mask))
			acl->a_flags |= ACL4_MASKED;
		acl->a_group_mask = group_mask;
	}
	if (acl_has & RICHACL_TEXT_OTHER_MASK) {
		if (!(acl_has & RICHACL_TEXT_FLAGS) &&
		    (acl->a_other_mask & ~other_mask))
			acl->a_flags |= ACL4_MASKED;
		acl->a_other_mask = other_mask;
	}
}

int modify_richacl(struct richacl **acl2, struct richacl *acl, int acl_has)
{
	struct richace *ace2, *ace;

	if (richacl_apply_masks(acl2))
		return -1;

	richacl_for_each_entry(ace, acl) {
		struct richacl *acl3;
		struct richace *ace3;

		richacl_for_each_entry(ace2, *acl2) {
			if (ace2->e_type == ace->e_type &&
			    richace_is_inherited(ace2) == richace_is_inherited(ace) &&
			    richace_is_same_identifier(ace, ace2)) {
				ace2->e_mask = ace->e_mask;
				ace2->e_flags = ace->e_flags;
				goto next_change;
			}
		}

		acl3 = richacl_alloc((*acl2)->a_count + 1);
		if (!acl3)
			return -1;
		acl3->a_flags = (*acl2)->a_flags;
		ace3 = acl3->a_entries;
		if (!(ace->e_flags & ACE4_INHERITED_ACE)) {
			if (richace_is_deny(ace)) {
				/*
				 * Insert the new deny entry after the existing
				 * initial non-inherited deny entries.
				 */
				richacl_for_each_entry(ace2, *acl2) {
					if (!richace_is_deny(ace2) ||
					    richace_is_inherited(ace2))
						break;
					richace_copy(ace3++, ace2);
				}
			} else {
				/*
				 * Append the new allow entry at the end of the
				 * non-inherited aces.
				 */
				richacl_for_each_entry(ace2, *acl2) {
					if (richace_is_inherited(ace2))
						break;
					richace_copy(ace3++, ace2);
				}
			}
			richace_copy(ace3++, ace);
			ace2--;
			richacl_for_each_entry_continue(ace2, *acl2)
				richace_copy(ace3++, ace2);
		} else {
			struct richace *last_inherited;

			last_inherited = (*acl2)->a_entries + (*acl2)->a_count;
			while (last_inherited > (*acl2)->a_entries &&
			       richace_is_inherited(last_inherited - 1))
				last_inherited--;

			richacl_for_each_entry(ace2, *acl2) {
				if (ace2 == last_inherited)
					break;
				richace_copy(ace3++, ace2);
			}
			if (richace_is_deny(ace)) {
				/*
				 * Insert the new deny entry after the existing
				 * initial inherited deny entries.
				 */
				ace2--;
				richacl_for_each_entry_continue(ace2, *acl2) {
					if (!richace_is_deny(ace2))
						break;
					richace_copy(ace3++, ace2);
				}
			} else {
				/*
				 * Append the new allow entry at the end of the
				 * inherited aces.
				 */
				ace2--;
				richacl_for_each_entry_continue(ace2, *acl2)
					richace_copy(ace3++, ace2);
			}
			richace_copy(ace3++, ace);
			ace2--;
			richacl_for_each_entry_continue(ace2, *acl2)
				richace_copy(ace3++, ace2);
		}

		richacl_free(*acl2);
		*acl2 = acl3;

	next_change:
		/* gcc is unhappy without a statement behind the label ... */ ;
	}

	if (acl_has & RICHACL_TEXT_FLAGS)
		(*acl2)->a_flags = acl->a_flags;
	if (acl_has & RICHACL_TEXT_OWNER_MASK)
		(*acl2)->a_owner_mask = acl->a_owner_mask;
	if (acl_has & RICHACL_TEXT_GROUP_MASK)
		(*acl2)->a_group_mask = acl->a_group_mask;
	if (acl_has & RICHACL_TEXT_OTHER_MASK)
		(*acl2)->a_other_mask = acl->a_other_mask;
	compute_masks(*acl2, acl_has);

	return 0;
}

static int auto_inherit(const char *dirname, struct richacl *dir_acl)
{
	DIR *dir;
	struct richacl *dir_inheritable, *file_inheritable;
	struct dirent *dirent;
	char *path = NULL;
	size_t dirname_len;
	int status = 0;

	dir = opendir(dirname);
	if (!dir) {
		if (errno == ENOTDIR)
			return 0;
		return -1;
	}

	dirname_len = strlen(dirname);
	path = malloc(dirname_len + 2);
	if (!path)
		goto fail;
	sprintf(path, "%s/", dirname);

	errno = 0;
	file_inheritable = richacl_inherit(dir_acl, 0);
	if (!file_inheritable && errno != 0)
		goto fail;
	dir_inheritable = richacl_inherit(dir_acl, 1);
	if (!dir_inheritable && errno != 0)
		goto fail;

	while ((errno = 0, dirent = readdir(dir))) {
		struct richacl *old_acl = NULL, *new_acl = NULL;
		int isdir;
		char *p;

		if (!strcmp(dirent->d_name, ".") ||
		    !strcmp(dirent->d_name, ".."))
			continue;

		p = realloc(path, strlen(dirname) + strlen(dirent->d_name) + 2);
		if (!p)
			goto fail;
		path = p;
		strcpy(path + dirname_len + 1, dirent->d_name);

		if (dirent->d_type == DT_UNKNOWN) {
			struct stat st;

			if (lstat(path, &st))
				goto fail2;
			dirent->d_type = IFTODT(st.st_mode);
		}
		if (dirent->d_type == DT_LNK)
			continue;
		isdir = (dirent->d_type == DT_DIR);

		old_acl = richacl_get_file(path);
		if (!old_acl) {
			if (errno == ENODATA || errno == ENOTSUP || errno == ENOSYS)
				goto next;
			goto fail2;
		}
		if (!richacl_is_auto_inherit(old_acl))
			goto next;
		if (old_acl->a_flags & ACL4_PROTECTED) {
			if (!opt_repropagate)
				goto next;
			new_acl = old_acl;
			old_acl = NULL;
		} else {
			int equal;
			new_acl = richacl_auto_inherit(old_acl,
					isdir ? dir_inheritable :
						file_inheritable);
			equal = !richacl_compare(old_acl, new_acl);
			if (equal && !opt_repropagate)
				goto next;
			if (!equal && richacl_set_file(path, new_acl))
				goto fail2;
		}

		if (isdir)
			if (auto_inherit(path, new_acl))
				goto fail2;

	next:
		free(old_acl);
		free(new_acl);
		continue;

	fail2:
		perror(path);
		free(old_acl);
		free(new_acl);
		free(path);
		status = -1;
	}
	if (errno != 0) {
		perror(dirname);
		status = -1;
	}
	free(path);
	closedir(dir);
	return status;

fail:
	perror(basename(progname));
	free(path);
	closedir(dir);
	return -1;
}

static struct richacl *get_richacl(const char *file, mode_t mode)
{
	struct richacl *acl;

	acl = richacl_get_file(file);
	if (!acl) {
		if (errno == ENOTSUP &&
		    (getxattr(file, "system.posix_acl_access", NULL, 0) >= 0 ||
		    (S_ISDIR(mode) &&
		     getxattr(file, "system.posix_acl_default", NULL, 0) >= 0))) {
			fprintf(stderr, "%s: POSIX ACL(s) exist\n", file);
			errno = 0;
			return NULL;
		} else if (errno == ENODATA || errno == ENOTSUP || errno == ENOSYS)
			acl = richacl_from_mode(mode);
	}
	return acl;
}

static int set_richacl(const char *path, struct richacl *acl)
{
	if (richacl_set_file(path, acl)) {
		struct stat st;

		if (stat(path, &st))
			return -1;
		if (!richacl_equiv_mode(acl, &st.st_mode))
			return chmod(path, st.st_mode);
		/* FIXME: We could try POSIX ACLs here as well. */
		return -1;
	}
	if (richacl_is_auto_inherit(acl)) {
		int ret;

		ret =  auto_inherit(path, acl);
		return ret;
	}
	return 0;
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
	printf("%s:\n", file);
	puts(text);
	free(text);
	return 0;

fail:
	return -1;
}

void remove_filename(struct string_buffer *buffer)
{
	char *c, *end;

	for (c = buffer->buffer, end = buffer->buffer + buffer->offset;
	     c != end;
	     c++) {
		if (*c == '\n')
			break;
		if (*c == ':') {
			c++;
			if (c == end)
				break;
			if (*c != '\n')
				continue;
			c++;
			memmove(buffer->buffer, c, end - c + 1);
			buffer->offset = end - c;
		}
	}
}

static struct option long_options[] = {
	{"access",		2, 0, 'a'},
	{"get",			0, 0, 'g'},
	{"modify",		1, 0, 'm'},
	{"modify-file",		1, 0, 'M'},
	{"set",			1, 0, 's'},
	{"set-file",		1, 0, 'S'},
	{"remove",		0, 0, 'r'},
	{"long",		0, 0, 'l'},
	{"raw",			0, 0,  1 },
	{"dry-run",		0, 0,  2 },
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

	fprintf(file, "SYNOPSIS: %s [options] {command} file ...\n",
		basename(progname));
	if (!help) {
		fprintf(file, "Try `%s --help' for more information.\n",
			basename(progname));
		exit(1);
	}
	fprintf(file,
"\n"
"Commands:\n"
"  --get, -g   Display the ACL of file(s). Multiple ACL entries are separated\n"
"              by newline.\n"
"  --modify acl_entries, -m acl_entries\n"
"              Modify the ACL of file(s) by replacing existing entries with\n"
"              the entries in acl_entries, and adding all new entries. When\n"
"              the permissions of an entry are empty, remove the entry.\n"
"  --set acl, -s acl\n"
"              Set the ACL of file(s) to acl. Multiple ACL entries are separated\n"
"              by whitespace or commas.\n"
"  --modify-file acl_entries_file, -M acl_entries_file\n"
"  --set-file acl_file, -S acl_file\n"
"              Identical to --modify / --set, but read the ACL from a file\n"
"              instead. If the file is `-', read from standard input.\n"
"  --remove, -r\n"
"              Remove the ACL of file(s).\n"
"  --access[=user[:group:...]}, -a[user[:group:...]}\n"
"              Show which permissions the caller or a specified user has for\n"
"              file(s).  When a list of groups is given, this overrides the\n"
"              groups the user is in.\n"
"              capabilities. \n"
"  --version, -v\n"
"              Display the version of %s and exit.\n"
"  --help, -h  This help text.\n"
"\n"
"Options:\n"
"  --long, -l  Display access masks and flags in their long form.\n"
"  --full      Also show permissions which are always implicitly allowed.\n"
"              Always allow those permissions when setting/modifying acls.\n"
"  --raw       Show acls as stored on the file system including the file masks.\n"
"              Implies --full.\n"
"  --unaligned\n"
"              Do not align acl entries or pad missing permissions with '-'.\n"
"  --numeric-ids\n"
"              Display numeric user and group IDs instead of names.\n"
"\n"
"ACL entries are represented by colon separated <who>:<mask>:<flags>:<type>\n"
"fields. The <who> field may be \"owner@\", \"group@\", \"everyone@\", a user\n"
"name or ID, or a group name or ID. Groups have the identifier_group(g) flag\n"
"set in the <flags> field. The <type> field may be \"allow\" or \"deny\".\n"
"The <mask> and <flags> fields are lists of single-letter abbreviations or\n"
"slash-separated names, or a combination of both.\n"
"\n"
"ACL entry <mask> values are:\n"
"\tread_data (r), list_directory (r), write_data (w), add_file (w),\n"
"\texecute (x), append_data (p), add_subdirectory (p), delete_child (d),\n"
"\tdelete (D), read_attributes (a), write_attributes (A), read_xattr (R),\n"
"\twrite_xattr (W), read_acl (c), write_acl (C), write_owner(o),\n"
"\tsynchronize (S), write_retention (e), write_retention_hold (E)\n"
"\n"
"ACL entry <flags> values are:\n"
"\tfile_inherit (f), dir_inherit (d),\n"
"\tno_propagate (n), inherit_only (i),\n"
"\tidentifier_group (g), inherited (a)\n"
"\n"
"ACL flag values are:\n"
"\tmasked (m), auto_inherit (a), protected (p), defaulted (d)" /* ", posix_mapped (P)" */ "\n",
	basename(progname));
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt_get = 0, opt_remove = 0, opt_access = 0, opt_dry_run = 0;
	int opt_modify = 0, opt_set = 0;
	int opt_full = 0;
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

	while ((c = getopt_long(argc, argv, "gm:M:s:S:a::rlvh",
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

			case 'a':  /* --access */
				opt_access = 1;
				opt_user = optarg;
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

			case 3:  /* --full */
				format &= ~RICHACL_TEXT_SIMPLIFY;
				opt_full = 1;
				break;

			case 4:  /* --unaligned */
				format &= ~RICHACL_TEXT_ALIGN;
				break;

			case 5:  /* --numeric-ids */
				format |= RICHACL_TEXT_NUMERIC_IDS;
				break;

			default:
				synopsis(0);
				break;
		}
	}
	if (opt_get + opt_remove + opt_modify + opt_set + opt_access != 1 ||
	    (acl_text ? 1 : 0) + (acl_file ? 1 : 0) > 1 ||
	    optind == argc)
		synopsis(optind != argc);

	if (acl_text) {
		acl = richacl_from_text(acl_text, &acl_has, printf_stderr);
		if (!acl)
			return 1;
		if (!opt_full)
			add_implicitly_granted_permissions(acl);
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

		remove_filename(buffer);
		acl = richacl_from_text(buffer->buffer, &acl_has, printf_stderr);
		if (!acl)
			return 1;
		free_string_buffer(buffer);
	}

	/* Compute all masks which haven't been set explicitly. */
	/* FIXME: how about --modify? */
	if (opt_set && acl)
		compute_masks(acl, acl_has);

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
		struct richacl *acl2 = NULL;
		struct stat st;

		if (opt_get || opt_modify || opt_access || opt_dry_run) {
			if (stat(file, &st))
				goto fail2;
		} else
			memset(&st, 0, sizeof(st));

		if (opt_set) {
			if (opt_dry_run) {
				if (print_richacl(file, &acl, &st, format))
					goto fail2;
			} else {
				if (set_richacl(file, acl))
					goto fail2;
			}
		} else if (opt_modify) {
			acl2 = get_richacl(file, st.st_mode);
			if (!acl2) {
				if (!errno)
					goto fail3;
				goto fail2;
			}
			if (modify_richacl(&acl2, acl, acl_has))
				goto fail2;
			if (opt_dry_run) {
				if (print_richacl(file, &acl2, &st, format))
					goto fail2;
			} else {
				if (set_richacl(file, acl2))
					goto fail2;
			}
		} else if (opt_remove) {
			if (removexattr(file, "system.richacl")) {
				if (errno != ENODATA)
					goto fail2;
			}
		} else if (opt_access) {
			unsigned int mask;
			char *mask_text;

			mask = richacl_access(file, &st, user, groups, n_groups);
			if (mask < 0)
				goto fail2;

			mask_text = richacl_mask_to_text(mask,
					format | format_for_mode(st.st_mode));
			printf("%s  %s\n", mask_text, file);
			free(mask_text);
		} else /* opt_get */ {
			acl2 = get_richacl(file, st.st_mode);
			if (!acl2) {
				if (!errno)
					goto fail3;
				goto fail2;
			}
			if (print_richacl(file, &acl2, &st, format))
				goto fail2;
		}
		richacl_free(acl2);
		continue;

	fail2:
		richacl_free(acl2);
		perror(file);
	fail3:
		status = 1;
	}

	richacl_free(acl);
	return status;

fail:
	perror(basename(progname));
	return 1;
}
