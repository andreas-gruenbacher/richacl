#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sys/richacl.h"

void print_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int main(int argc, char *argv[])
{
	struct richacl *dir_acl, *acl;
	char *text;
	int isdir = 0;
	int opt;

	while ((opt = getopt(argc, argv, "dm:")) != -1) {
		switch(opt) {
		case 'd':
			isdir = 1;
			break;

		default:
			goto usage;
		}
	}
	if (optind + 1 != argc)
		goto usage;

	dir_acl = richacl_from_text(argv[optind], NULL, print_error);
	if (!dir_acl) {
		perror(argv[optind]);
		return 1;
	}
	acl = richacl_inherit(dir_acl, isdir);
	text = richacl_to_text(acl,
		(isdir ? RICHACL_TEXT_DIRECTORY_CONTEXT :
			 RICHACL_TEXT_FILE_CONTEXT) |
		RICHACL_TEXT_SIMPLIFY |
		RICHACL_TEXT_NUMERIC_IDS |
		RICHACL_TEXT_ALIGN);
	printf("%s\n", text);
	return 0;

usage:
	fprintf(stderr, "Usage: %s [-d] acl ...\n", argv[0]);
	return 1;
}
