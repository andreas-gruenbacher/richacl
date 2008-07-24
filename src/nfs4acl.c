/*
 * Copyright (C) 2006-2008 Andreas Gruenbacher <agruen@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/*
 * FIXME: Make ls show a `+' for nfs4acls (in coreutils).
 */

#define _GNU_SOURCE
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

#include "nfs4acl.h"
#include "string_buffer.h"

static const char *progname;

void printf_stderr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#if 0
struct nfs4acl *modify_nfs4acl(struct nfs4acl *old_acl, size_t *old_acl_size,
			       struct nfs4acl *acl)
{
	struct nfs4ace *old_ace, *ace;
	unsigned int m, n;

	nfs4acl_for_each_entry(m, ace, acl) {
		int found = 0;

		nfs4acl_for_each_entry(n, old_ace, old_acl) {
			if (old_ace->e_type == ace->e_type &&
			    ((old_ace->e_flags & ACE4_IDENTIFIER_GROUP) ==
			     (ace->e_flags & ACE4_IDENTIFIER_GROUP)) &&
			    old_ace->e_id == ace->e_id &&
			    !strcmp(old_ace->e_who, ace->e_who)) {
				old_ace->e_mask = ace->e_mask;
				old_ace->e_flags = ace->e_flags;
				found = 1;
			}
		}
		if (!found) {
			size_t ace_size = NFS4ACE_SIZE(ace->e_who);
			size_t offset;

			old_acl = NOFAIL(realloc(old_acl, *old_acl_size + ace_size));
			if (ace->e_type == ACE4_ACCESS_DENIED_ACE_TYPE) {
				nfs4acl_for_each_entry(n, old_ace, old_acl) {
					if (old_ace->e_type == ACE4_ACCESS_DENIED_ACE_TYPE)
						continue;
					offset = (void *)old_ace - (void *)old_acl;
					break;
				}
			} else
				offset = *old_acl_size;
			memmove((void *)old_acl + offset + ace_size,
				(void *)old_acl + offset,
				*old_acl_size - offset);
			memcpy((void *)old_acl + offset, ace, ace_size);
			*old_acl_size += ace_size;
			old_acl->a_count++;
		}
	}

	if (!opt_no_masks &&
	    (acl->a_flags & (OWNER_MASK_UNSET | GROUP_MASK_UNSET | OTHER_MASK_UNSET)))
		nfs4acl_compute_max_masks(old_acl);

	if (!(acl->a_flags & OWNER_MASK_UNSET))
		old_acl->a_owner_mask = acl->a_owner_mask;
	if (!(acl->a_flags & GROUP_MASK_UNSET))
		old_acl->a_group_mask = acl->a_group_mask;
	if (!(acl->a_flags & OTHER_MASK_UNSET))
		old_acl->a_other_mask = acl->a_other_mask;

	old_acl->a_flags &= ~(OWNER_MASK_UNSET | GROUP_MASK_UNSET | OTHER_MASK_UNSET);

	return old_acl;
}
#endif

static int print_nfs4acl(const char *file, struct nfs4acl *acl, int fmt)
{
	char *text;

	if (!(fmt & NFS4ACL_TEXT_SHOW_MASKS)) {
		if (nfs4acl_apply_masks(&acl))
			goto fail;
	}
	text = nfs4acl_to_text(acl, fmt);
	if (!text)
		goto fail;
	printf("%s:\n", file);
	puts(text);
	free(text);
	nfs4acl_free(acl);
	return 0;

fail:
	nfs4acl_free(acl);
	return -1;
}
static struct option long_options[] = {
	{"get",			0, 0, 'g'},
#if 0
	{"modify",		1, 0, 'm'},
	{"modify-file",		1, 0, 'M'},
#endif
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

	fprintf(file, "SYNOPSIS: %s options] {command} file ...\n",
		basename(progname));
	if (!help)
		exit(1);
	fprintf(file,
"\n"
"Commands:\n"
"  --get       Display the ACL of file(s). Multiple ACL entries are separated\n"
"              by newline.\n"
#if 0
"  --modify acl_entries\n"
"              Modify the ACL of file(s) by replacing existing entries with\n"
"              the entries in acl_entries, and adding all new entries.\n"
#endif
"  --set acl   Set the ACL of file(s) to acl. Multiple ACL entries are\n"
"              separated by whitespace or commas.\n"
#if 0
"  --modify-file acl_entries_file, --set-file acl_file\n"
"              Identical to --modify / --set, but read the ACL from a file\n"
"              instead. If the file is `-', read from standard input.\n"
#else
"  --set-file acl_file\n"
"              Identical to --set, but read the ACL from a file\n"
"              instead. If the file is `-', read from standard input.\n"
#endif
"  --delete-acl\n"
"              Delete the ACL of file(s).\n"
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
"\tidentifier_group (g)\n",
	basename(progname));
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt_get = 0, opt_remove = 0, opt_dry_run = 0;
	int opt_modify = 0, opt_set = 0;
	char *acl_text = NULL, *acl_file = NULL;
	int format = NFS4ACL_TEXT_SIMPLIFY;
	int status = 0;
	int c;

	struct nfs4acl *acl = NULL;

	progname = argv[0];

	while ((c = getopt_long(argc, argv, "gm:M:s:S:nrlvh",
				long_options, NULL)) != -1) {
		switch(c) {
			case 'g':
				opt_get = 1;
				break;
#if 0
			case 'm':
				opt_modify = 1;
				acl_text = optarg;
				break;

			case 'M':
				opt_modify = 1;
				acl_file = optarg;
				break;
#endif
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
				format |= NFS4ACL_TEXT_LONG;
				break;

			case 'v':
				printf("%s %s\n", basename(progname), VERSION);
				exit(0);

			case 'h':
				synopsis(1);
				break;

			case 1:  /* --raw */
				format |= NFS4ACL_TEXT_SHOW_MASKS;
				format &= ~NFS4ACL_TEXT_SIMPLIFY;
				break;

			case 2:  /* --dry-run */
				opt_dry_run = 1;
				break;

			default:
				synopsis(0);
				break;
		}
	}
	if (opt_get + opt_remove + opt_modify + opt_set != 1 ||
	    (acl_text ? 1 : 0) + (acl_file ? 1 : 0) > 1 ||
	    optind == argc)
		synopsis(argc == 1);

	if (acl_text) {
		acl = nfs4acl_from_text(acl_text, printf_stderr);
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

		acl = nfs4acl_from_text(buffer->buffer, printf_stderr);
		if (!acl)
			return 1;
		free_string_buffer(buffer);
	}

	if (acl) {
		/* Compute all masks which haven't been set explicitly. */
		if (acl->a_owner_mask == -1 ||
		    acl->a_group_mask == -1 ||
		    acl->a_other_mask == -1) {
			unsigned int owner_mask = acl->a_owner_mask;
			unsigned int group_mask = acl->a_group_mask;
			unsigned int other_mask = acl->a_other_mask;

			nfs4acl_compute_max_masks(acl);
			if (owner_mask != -1)
				acl->a_owner_mask = owner_mask;
			if (group_mask != -1)
				acl->a_group_mask = group_mask;
			if (other_mask != -1)
				acl->a_other_mask = other_mask;
		}
	}

	if (opt_dry_run && opt_set) {
		if (print_nfs4acl("<no file>", acl, format |
				NFS4ACL_TEXT_FILE_CONTEXT |
				NFS4ACL_TEXT_DIRECTORY_CONTEXT)) {
			perror("");
			return 1;
		}
		return 0;
	}

	for (; optind < argc; optind++) {
		const char *file = argv[optind];

#if 0
		if (opt_modify) {
			struct nfs4acl *old_acl;
			size_t old_acl_size;

			old_acl = get_nfs4acl(file, system_nfs4acl, &old_acl_size);
			if (!old_acl) {
#if 0
				old_acl = NOFAIL(malloc(sizeof(struct nfs4acl)));
				memset(old_acl, 0, sizeof(struct nfs4acl));
				acl->a_version = ACL4_XATTR_VERSION;
#else
				struct stat st;

				if (stat(file, &st)) {
					perror(file);
					status = 1;
					continue;
				}
				old_acl = nfs4acl_from_mode(st.st_mode, &old_acl_size);
#endif
			}
			old_acl = modify_nfs4acl(old_acl, &old_acl_size, acl);
			if (opt_dry_run) {
				if (!buffer)
					buffer = NOFAIL(alloc_grow_buffer(1024));
				write_nfs4acl(buffer, old_acl, -1,
					      NONDIR_MASK | DIR_MASK, '\n', 1);
				puts(buffer->buffer);
				reset_grow_buffer(buffer);
				continue;
			}
			nfs4acl_to_big_endian(old_acl);
			if (setxattr(file, system_nfs4acl, old_acl, old_acl_size, 0)) {
				perror(file);
				status = 1;
			}
			free(old_acl);
		} else
#endif
		if (opt_set) {
			if (nfs4acl_set_file(file, acl)) {
				perror(file);
				status = 1;
			}
		} else if (opt_remove) {
			if (removexattr(file, "system.nfs4acl")) {
				if (errno != ENODATA) {
					perror(file);
					status = 1;
				}
			}
		} else {
			struct nfs4acl *acl2;
			struct stat st;

			if (stat(file, &st))
				goto fail;

			acl2 = nfs4acl_get_file(file);
			if (!acl2) {
				switch(errno) {
					case ENODATA: case ENOSYS: case ENOTSUP:
						acl2 = nfs4acl_from_mode(st.st_mode);
						break;
					default:
						goto fail;
				}
			}

			if (print_nfs4acl(file, acl2,
					  format | (S_ISDIR(st.st_mode) ?
						    NFS4ACL_TEXT_DIRECTORY_CONTEXT :
						    NFS4ACL_TEXT_FILE_CONTEXT)))
				goto fail;
			continue;

		fail:
			perror(file);
			status = 1;
		}
	}

	nfs4acl_free(acl);
	return status;
}
