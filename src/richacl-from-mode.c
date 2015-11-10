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
	struct richacl *acl;
	mode_t file_type = S_IFREG;
	bool masking = false;
	int opt;

	while ((opt = getopt(argc, argv, "dm")) != -1) {
		switch(opt) {
		case 'd':
			file_type = S_IFDIR;
			break;

		case 'm':
			masking = true;
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

		if (masking) {
			struct richace *ace;

			acl = richacl_alloc(1);
			if (!acl) {
				perror(argv[optind]);
				return 1;
			}
			ace = acl->a_entries;
			ace->e_mask = S_ISDIR(mode) ?
				RICHACE_POSIX_MODE_ALL :
				(RICHACE_POSIX_MODE_ALL & ~RICHACE_DELETE_CHILD);
			richace_set_special_who(ace, "EVERYONE@");
			richacl_chmod(acl, mode);
			if (richacl_apply_masks(&acl, getuid())) {
				perror(argv[optind]);
				return 1;
			}
		} else {
			acl = richacl_from_mode(mode);
			if (!acl) {
				perror(argv[optind]);
				return 1;
			}
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
		richacl_free(acl);
		free(text);
	}
	return 0;

usage:
	fprintf(stderr, "Usage: %s [-dm] mode ...\n", argv[0]);
	return 1;
}
