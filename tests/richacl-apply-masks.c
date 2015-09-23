#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "richacl.h"

void print_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int main(int argc, char *argv[])
{
	uid_t owner = getuid();
	mode_t mode = 0;
	bool do_chmod = false, do_create = false;
	int opt;

	while ((opt = getopt(argc, argv, "m:c:d")) != -1) {
		switch(opt) {
		case 'm':
			mode = (mode & ~0777) | strtoul(optarg, NULL, 8);
			do_chmod = true;
			break;

		case 'c':
			mode = (mode & ~0777) | strtoul(optarg, NULL, 8);
			do_create = true;
			break;

		case 'd':
			mode |= S_IFDIR;
			break;

		default:
			goto usage;
		}
	}
	if (optind == argc)
		goto usage;

	for (; optind < argc; optind++) {
		struct richacl *acl;
		char *text;

		acl = richacl_from_text(argv[optind], NULL, print_error);
		if (!acl) {
			perror(argv[optind]);
			return 1;
		}
		if (do_chmod || do_create) {
			richacl_chmod(acl, mode);
			if (do_create)
				acl->a_flags &= ~RICHACL_WRITE_THROUGH;
		}
		richacl_apply_masks(&acl, owner);
		text = richacl_to_text(acl, RICHACL_TEXT_NUMERIC_IDS);
		printf("%s\n", text);
		free(text);
	}
	return 0;

usage:
	fprintf(stderr, "Usage: %s acl ...\n", argv[0]);
	return 1;
}
