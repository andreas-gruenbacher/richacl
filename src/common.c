#include <sys/types.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include "richacl.h"
#include "common.h"

bool
supports_posix_acls(const char *file)
{
	ssize_t ret = getxattr(file, "system.posix_acl_access", NULL, 0);
	if (ret >= 0 || (errno != ENOSYS && errno != ENOTSUP)) {
		fprintf(stderr, "%s: File system supports posix acls instead of richacls\n",
			file);
		return true;
	}
	return false;
}

struct richacl *get_richacl(const char *file, mode_t mode)
{
	struct richacl *acl;

	acl = richacl_get_file(file);
	if (!acl) {
		if (errno != ENOSYS && supports_posix_acls(file)) {
			errno = 0;
			return NULL;
		} else if (errno == ENODATA || errno == ENOTSUP || errno == ENOSYS)
			acl = richacl_from_mode(mode);
	}
	return acl;
}
