#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

int main(int argc, char *argv[])
{
	char **args;
	int n, ret;

	if (argc < 4) {
		fprintf(stderr, "USAGE: %s uid gid command ...\n", basename(argv[0]));
		return 2;
	}

	args = alloca(sizeof(*args) * argc - 3);
	for (n = 0; n < argc - 3; n++)
		args[n] = argv[n + 3];
	args[n] = NULL;

	ret = setgroups(0, NULL);
	if (ret != 0) {
		perror("Setting supplementary groups");
		return 2;
	}

	ret = setgid(atoi(argv[2]));
	if (ret != 0) {
		fprintf(stderr, "Setting the group id to %d: %s\n",
			atoi(argv[2]),
			strerror(errno));
		return 2;
	}

	setuid(atoi(argv[1]));
	if (ret != 0) {
		fprintf(stderr, "Setting the user id to %d: %s\n",
			atoi(argv[1]),
			strerror(errno));
		return 2;
	}

	ret = execvp(args[0], args);
	perror(args[0]);
	return 2;
}
