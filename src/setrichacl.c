/*
  Copyright (C) 2006, 2008, 2009, 2010  Novell, Inc.
  Copyright (C) 2015  Red Hat, Inc.
  Written by Andreas Gruenbacher <agruenba@redhat.com>

  The setrichacl program is free software; you can redistribute it
  and/or modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2, or (at
  your option) any later version.

  The setrichacl program is distributed in the hope that it will be
  useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * FIXME:
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
#include "common.h"

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

static void compute_masks(struct richacl *acl, int what_acl_contains, uid_t owner)
{
	unsigned int owner_mask = acl->a_owner_mask;
	unsigned int group_mask = acl->a_group_mask;
	unsigned int other_mask = acl->a_other_mask;

	if ((what_acl_contains & RICHACL_TEXT_OWNER_MASK) &&
	    (what_acl_contains & RICHACL_TEXT_GROUP_MASK) &&
	    (what_acl_contains & RICHACL_TEXT_OTHER_MASK) &&
	    (what_acl_contains & RICHACL_TEXT_FLAGS))
		return;

	if (!(what_acl_contains & RICHACL_TEXT_FLAGS))
		acl->a_flags &= ~RICHACL_MASKED;
	richacl_compute_max_masks(acl, owner);
	if (what_acl_contains & RICHACL_TEXT_OWNER_MASK) {
		if (!(what_acl_contains & RICHACL_TEXT_FLAGS) &&
		    (acl->a_owner_mask & ~owner_mask))
			acl->a_flags |= RICHACL_MASKED;
		acl->a_owner_mask = owner_mask;
	}
	if (what_acl_contains & RICHACL_TEXT_GROUP_MASK) {
		if (!(what_acl_contains & RICHACL_TEXT_FLAGS) &&
		    (acl->a_group_mask & ~group_mask))
			acl->a_flags |= RICHACL_MASKED;
		acl->a_group_mask = group_mask;
	}
	if (what_acl_contains & RICHACL_TEXT_OTHER_MASK) {
		if (!(what_acl_contains & RICHACL_TEXT_FLAGS) &&
		    (acl->a_other_mask & ~other_mask))
			acl->a_flags |= RICHACL_MASKED;
		acl->a_other_mask = other_mask;
	}
}

static int modify_richacl(struct richacl **acl2, struct richacl *acl, int what_acl_contains, uid_t owner)
{
	struct richace *ace2, *ace;

	if (richacl_apply_masks(acl2, owner))
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
		if (!(ace->e_flags & RICHACE_INHERITED_ACE)) {
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

	if (what_acl_contains & RICHACL_TEXT_FLAGS)
		(*acl2)->a_flags = acl->a_flags;
	if (what_acl_contains & RICHACL_TEXT_OWNER_MASK)
		(*acl2)->a_owner_mask = acl->a_owner_mask;
	if (what_acl_contains & RICHACL_TEXT_GROUP_MASK)
		(*acl2)->a_group_mask = acl->a_group_mask;
	if (what_acl_contains & RICHACL_TEXT_OTHER_MASK)
		(*acl2)->a_other_mask = acl->a_other_mask;
	compute_masks(*acl2, what_acl_contains, owner);

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
	errno = 0;
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
		if (old_acl->a_flags & RICHACL_PROTECTED) {
			if (!opt_repropagate)
				goto next;
			new_acl = old_acl;
			old_acl = NULL;
		} else {
			struct stat st;
			int equal;

			if (stat(path, &st)) {
				richacl_free(old_acl);
				goto fail2;
			}

			if (old_acl->a_flags & RICHACL_DEFAULTED) {
				/* RFC 5661: An application performing
				 * automatic inheritance takes the
				 * RICHACL_DEFAULTED flag as a sign that the acl
				 * should be completely replaced by one
				 * generated using the automatic inheritance
				 * rules. */

				free(old_acl);
				old_acl = richacl_alloc(0);
				old_acl->a_flags |= RICHACL_AUTO_INHERIT;
			}
			new_acl = richacl_auto_inherit(old_acl,
					isdir ? dir_inheritable :
						file_inheritable);
			richacl_compute_max_masks(new_acl, st.st_uid);
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

static int set_richacl(const char *path, struct richacl *acl)
{
	if (richacl_set_file(path, acl)) {
		int saved_errno = errno;
		struct stat st;

		if (stat(path, &st))
			return -1;
		if (!richacl_equiv_mode(acl, &st.st_mode))
			return chmod(path, st.st_mode);
		if (saved_errno != ENOSYS && has_posix_acl(path, st.st_mode))
			errno = 0;
		return -1;
	}
	if (richacl_is_auto_inherit(acl)) {
		int ret;

		ret =  auto_inherit(path, acl);
		return ret;
	}
	return 0;
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
	{"modify",		1, 0, 'm'},
	{"modify-file",		1, 0, 'M'},
	{"set",			1, 0, 's'},
	{"set-file",		1, 0, 'S'},
	{"remove",		0, 0, 'b'},
	{"version",		0, 0, 'v'},
	{"help",		0, 0, 'h'},
	{ NULL,			0, 0,  0 }
};

static void synopsis(int help)
{
	FILE *file = help ? stdout : stderr;

	fprintf(file, "SYNOPSIS: %s {options} file ...\n",
		basename(progname));
	if (!help) {
		fprintf(file, "Try `%s --help' for more information.\n",
			basename(progname));
		exit(1);
	}
	fprintf(file,
"\n"
"Options:\n"
"  --modify acl_entries, -m acl_entries\n"
"              Modify the acl of file(s) by replacing existing entries with\n"
"              the entries in acl_entries, and adding all new entries. When\n"
"              the permissions of an entry are empty, remove the entry.\n"
"  --set acl_entries, -s acl_entries\n"
"              Set the acl of file(s) to acl. Multiple acl entries are separated\n"
"              by whitespace or commas.\n"
"  --modify-file acl_entries_file, -M acl_entries_file\n"
"  --set-file acl_entries_file, -S acl_entries_file\n"
"              Identical to --modify / --set, but read the acl from a file\n"
"              instead. If the file is `-', read from standard input.\n"
"  --remove, -b\n"
"              Remove all extended permissions and revert to the file mode.\n"
"  --version, -v\n"
"              Display the version of %s and exit.\n"
"  --help, -h  This help text.\n"
"\n"
"In all commands, multiple acl entries are comma or whitespace separated.\n"
COMMON_HELP,
	basename(progname));
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt_remove = 0, opt_modify = 0, opt_set = 0;
	char *acl_text = NULL, *acl_file = NULL;
	int status = 0;
	int c;

	struct richacl *acl = NULL;
	int what_acl_contains;

	progname = argv[0];

	while ((c = getopt_long(argc, argv, "m:M:s:S:bvh",
				long_options, NULL)) != -1) {
		switch(c) {
			case 'm':  /* --modify */
				opt_modify = 1;
				acl_text = optarg;
				break;

			case 'M':  /* --modify-file */
				opt_modify = 1;
				acl_file = optarg;
				break;
			case 's':  /* --set */
				opt_set = 1;
				acl_text = optarg;
				break;

			case 'S':  /* --set-file */
				opt_set = 1;
				acl_file = optarg;
				break;

			case 'b':  /*  --remove */
				opt_remove = 1;
				break;

			case 'v':  /* --version */
				printf("%s %s\n", basename(progname), VERSION);
				exit(0);

			case 'h':  /* --help */
				synopsis(1);
				break;

			default:
				synopsis(0);
				break;
		}
	}
	if (opt_remove + opt_modify + opt_set != 1 ||
	    (acl_text ? 1 : 0) + (acl_file ? 1 : 0) > 1 ||
	    optind == argc)
		synopsis(optind != argc);

	if (acl_text) {
		acl = richacl_from_text(acl_text, &what_acl_contains, printf_stderr);
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

		remove_filename(buffer);
		acl = richacl_from_text(buffer->buffer, &what_acl_contains, printf_stderr);
		if (!acl)
			return 1;
		free_string_buffer(buffer);
	}

	for (; optind < argc; optind++) {
		const char *file = argv[optind];
		struct richacl *acl2 = NULL;
		struct stat st;

		if (opt_set || opt_modify) {
			if (stat(file, &st))
				goto fail;
		} else
			memset(&st, 0, sizeof(st));

		if (opt_set) {
			if (acl) {
				/* Compute all masks which haven't been set explicitly. */
				compute_masks(acl, what_acl_contains, st.st_uid);
			}
			if (set_richacl(file, acl))
				goto fail;
		} else if (opt_modify) {
			acl2 = get_richacl(file, st.st_mode);
			if (!acl2)
				goto fail;
			if (modify_richacl(&acl2, acl, what_acl_contains, st.st_uid))
				goto fail;
			if (set_richacl(file, acl2))
				goto fail;
		} else if (opt_remove) {
			if (removexattr(file, "system.richacl")) {
				if (errno != ENODATA)
					goto fail;
			}
		}
		richacl_free(acl2);
		continue;

	fail:
		if (acl2)
			richacl_free(acl2);
		if (errno != 0)
			perror(file);
		status = 1;
	}

	richacl_free(acl);
	return status;
}
