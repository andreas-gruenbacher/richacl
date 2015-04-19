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
	int saved_errno = errno;
	ssize_t err;
	bool ret = false;

	err = getxattr(path, "system.posix_acl_access", NULL, 0);
	if (err < 0) {
		if (errno != ENODATA || !S_ISDIR(mode))
			goto out;
		err = getxattr(path, "system.posix_acl_default", NULL, 0);
		if (err < 0)
			goto out;
	}
	fprintf(stderr, "%s: File has a posix acl\n", path);
out:
	errno = saved_errno;
	return ret;
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
