#ifndef __NFS4ACL_XATTR_H
#define __NFS4ACL_XATTR_H

#include <arpa/inet.h>
#include <stdint.h>

struct nfs4ace_xattr {
	uint16_t	e_type;
	uint16_t	e_flags;
	uint32_t	e_mask;
	uint32_t	e_id;
	char		e_who[0];
};

struct nfs4acl_xattr {
	unsigned char	a_version;
	unsigned char	a_flags;
	uint16_t	a_count;
	uint32_t	a_owner_mask;
	uint32_t	a_group_mask;
	uint32_t	a_other_mask;
};

#define SYSTEM_NFS4ACL		"system.nfs4acl"
#define ACL4_XATTR_VERSION	0
#define ACL4_XATTR_MAX_COUNT	1024

#endif  /* __NFS4ACL_XATTR_H */
