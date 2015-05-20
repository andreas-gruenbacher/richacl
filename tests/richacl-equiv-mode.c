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
	struct richacl *acl;
	mode_t mode = S_IFREG;
	bool do_chmod = false;
	int opt;

	while ((opt = getopt(argc, argv, "dm:")) != -1) {
		switch(opt) {
		case 'd':
			mode = S_IFDIR | (mode & 07777);
			break;

		case 'm':
			mode = (mode & ~07777) | strtoul(optarg, NULL, 8);
			do_chmod = true;
			break;

		default:
			goto usage;
		}
	}
	if (optind + 1 != argc)
		goto usage;

	acl = richacl_from_text(argv[optind], NULL, print_error);
	if (!acl) {
		perror(argv[optind]);
		return 1;
	}

	if (do_chmod)
		richacl_chmod(acl, mode);

	if (richacl_equiv_mode(acl, &mode) == 0)
		printf("%03o\n", mode & 07777);
	else
		printf("no\n");
	return 0;

usage:
	fprintf(stderr, "Usage: %s [-d] [-m mode] acl\n", argv[0]);
	return 1;
}
