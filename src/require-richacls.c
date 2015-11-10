#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/xattr.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

int main(int argc, char *argv[])
{
	int ret;

	ret = getxattr(".", "system.richacl", NULL, 0);
	if (ret < 0 && errno != ENODATA) {
		char cwd[PATH_MAX];

		if (!getcwd(cwd, sizeof(cwd)))
			strcpy(cwd, ".");
		if (errno == ENOTSUP) {
			printf("This test requires a filesystem with richacl "
			       "support at %s\n",
			       cwd);
			return 77;
		} else {
			perror(cwd);
			return 1;
		}
	}
	return 0;
}
