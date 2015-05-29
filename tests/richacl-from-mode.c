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
	mode_t file_type = S_IFREG;
	int opt;

	while ((opt = getopt(argc, argv, "d")) != -1) {
		switch(opt) {
		case 'd':
			file_type = S_IFDIR;
			break;

		default:
			goto usage;
		}
	}
	if (optind == argc)
		goto usage;

	for (; optind < argc; optind++) {
		mode_t mode = file_type | strtoul(argv[optind], NULL, 0);
		char *text;

		acl = richacl_from_mode(mode);
		if (!acl) {
			perror(argv[optind]);
			return 1;
		}

		text = richacl_to_text(acl, RICHACL_TEXT_NUMERIC_IDS);
		if (!text) {
			perror(argv[optind]);
			return 1;
		}
		printf("%c%c%c%c%c%c%c%c%c%c\n%s\n",
		       S_ISDIR(mode) ? 'd' : '-',
		       mode & S_IRUSR ? 'r' : '-',
		       mode & S_IWUSR ? 'w' : '-',
		       mode & S_IXUSR ? 'x' : '-',
		       mode & S_IRGRP ? 'r' : '-',
		       mode & S_IWGRP ? 'w' : '-',
		       mode & S_IXGRP ? 'x' : '-',
		       mode & S_IROTH ? 'r' : '-',
		       mode & S_IWOTH ? 'w' : '-',
		       mode & S_IXOTH ? 'x' : '-',
		       text);
		free(text);
		richacl_free(acl);
	}
	return 0;

usage:
	fprintf(stderr, "Usage: %s [-d] mode ...\n", argv[0]);
	return 1;
}
