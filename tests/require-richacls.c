#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <libgen.h>

int main(int argc, char *argv[])
{
	const char *abs_top_builddir;
	char *path;
	int ret;

	abs_top_builddir = getenv("abs_top_builddir");
	if (!abs_top_builddir)
		abs_top_builddir = ".";
	ret = asprintf(&path, "%s/tests", abs_top_builddir);
	if (ret < 0) {
		fprintf(stderr, "%s: Out of memory\n", basename(argv[0]));
		return 1;
	}

	ret = getxattr(path, "system.richacl", NULL, 0);
	if (ret < 0 && errno != ENODATA) {
		if (errno == ENOTSUP) {
			printf("This test requires a file system with richacl support\n");
			return 77;
		} else {
			perror(path);
			return 1;
		}
	}
	return 0;
}
