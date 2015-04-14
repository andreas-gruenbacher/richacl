#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include "richacl.h"
#include "common.h"

bool
has_posix_acl(const char *path, mode_t mode)
{
	ssize_t ret;

	ret = getxattr(path, "system.posix_acl_access", NULL, 0);
	if (ret < 0) {
		if (errno != ENODATA || !S_ISDIR(mode))
			return false;
		ret = getxattr(path, "system.posix_acl_default", NULL, 0);
		if (ret < 0)
			return false;
	}
	fprintf(stderr, "%s: File has a posix acl\n", path);
	return true;
}

struct richacl *get_richacl(const char *file, mode_t mode)
{
	struct richacl *acl;

	acl = richacl_get_file(file);
	if (!acl) {
		if (errno != ENOSYS && has_posix_acl(file, mode)) {
			errno = 0;
			return NULL;
		} else if (errno == ENODATA || errno == ENOTSUP || errno == ENOSYS)
			acl = richacl_from_mode(mode);
	}
	return acl;
}
