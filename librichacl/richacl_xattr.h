#ifndef __RICHACL_XATTR_H
#define __RICHACL_XATTR_H

#include <arpa/inet.h>
#include <stdint.h>

struct richace_xattr {
	uint16_t	e_type;
	uint16_t	e_flags;
	uint32_t	e_mask;
	uint32_t	e_id;
	char		e_who[0];
};

struct richacl_xattr {
	unsigned char	a_version;
	unsigned char	a_flags;
	uint16_t	a_count;
	uint32_t	a_owner_mask;
	uint32_t	a_group_mask;
	uint32_t	a_other_mask;
};

#define SYSTEM_RICHACL		"system.richacl"
#define ACL4_XATTR_VERSION	0
#define ACL4_XATTR_MAX_COUNT	1024

#endif  /* __RICHACL_XATTR_H */
