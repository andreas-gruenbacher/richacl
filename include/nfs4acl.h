#ifndef __NFS4ACL_H
#define __NFS4ACL_H

#include <sys/types.h>
#include <string.h>

/* a_flags values */
#define ACL4_WRITE_THROUGH		0x01

#define ACL4_VALID_FLAGS \
	ACL4_WRITE_THROUGH

/* e_type values */
#define ACE4_ACCESS_ALLOWED_ACE_TYPE    0x0000
#define ACE4_ACCESS_DENIED_ACE_TYPE     0x0001

/* e_flags bitflags */
#define ACE4_FILE_INHERIT_ACE		0x0001
#define ACE4_DIRECTORY_INHERIT_ACE	0x0002
#define ACE4_NO_PROPAGATE_INHERIT_ACE	0x0004
#define ACE4_INHERIT_ONLY_ACE		0x0008
#define ACE4_IDENTIFIER_GROUP		0x0040

#define ACE4_VALID_FLAGS ( \
	ACE4_FILE_INHERIT_ACE | \
	ACE4_DIRECTORY_INHERIT_ACE | \
	ACE4_NO_PROPAGATE_INHERIT_ACE | \
	ACE4_INHERIT_ONLY_ACE | \
	ACE4_IDENTIFIER_GROUP )

/* e_mask bitflags */
#define ACE4_READ_DATA			0x00000001
#define ACE4_LIST_DIRECTORY		0x00000001
#define ACE4_WRITE_DATA			0x00000002
#define ACE4_ADD_FILE			0x00000002
#define ACE4_APPEND_DATA		0x00000004
#define ACE4_ADD_SUBDIRECTORY		0x00000004
#define ACE4_READ_NAMED_ATTRS		0x00000008
#define ACE4_WRITE_NAMED_ATTRS		0x00000010
#define ACE4_EXECUTE			0x00000020
#define ACE4_DELETE_CHILD		0x00000040
#define ACE4_READ_ATTRIBUTES		0x00000080
#define ACE4_WRITE_ATTRIBUTES		0x00000100
#define ACE4_DELETE			0x00010000
#define ACE4_READ_ACL			0x00020000
#define ACE4_WRITE_ACL			0x00040000
#define ACE4_WRITE_OWNER		0x00080000
#define ACE4_SYNCHRONIZE		0x00100000

#define ACE4_VALID_MASK ( \
	ACE4_READ_DATA | ACE4_LIST_DIRECTORY | \
	ACE4_WRITE_DATA | ACE4_ADD_FILE | \
	ACE4_APPEND_DATA | ACE4_ADD_SUBDIRECTORY | \
	ACE4_READ_NAMED_ATTRS | \
	ACE4_WRITE_NAMED_ATTRS | \
	ACE4_EXECUTE | \
	ACE4_DELETE_CHILD | \
	ACE4_READ_ATTRIBUTES | \
	ACE4_WRITE_ATTRIBUTES | \
	ACE4_DELETE | \
	ACE4_READ_ACL | \
	ACE4_WRITE_ACL | \
	ACE4_WRITE_OWNER | \
	ACE4_SYNCHRONIZE )

struct nfs4ace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	union {
		id_t		e_id;
		const char	*e_who;
	} u;
};

struct nfs4acl {
	unsigned char	a_flags;
	unsigned short	a_count;
	unsigned int	a_owner_mask;
	unsigned int	a_group_mask;
	unsigned int	a_other_mask;
	struct nfs4ace  a_entries[0];
};

#define nfs4acl_for_each_entry(_ace, _acl) \
	for (_ace = _acl->a_entries; \
	     _ace != _acl->a_entries + _acl->a_count; \
	     _ace++)

#define nfs4acl_for_each_entry_reverse(_ace, _acl) \
	for (_ace = _acl->a_entries + _acl->a_count - 1; \
	     _ace != _acl->a_entries - 1; \
	     _ace--)

#define NFS4ACL_TEXT_LONG		1
#define NFS4ACL_TEXT_FILE_CONTEXT	2
#define NFS4ACL_TEXT_DIRECTORY_CONTEXT	4
#define NFS4ACL_TEXT_SHOW_MASKS		8
#define NFS4ACL_TEXT_SIMPLIFY		16

extern int nfs4ace_is_owner(const struct nfs4ace *ace);
extern int nfs4ace_is_group(const struct nfs4ace *ace);
extern int nfs4ace_is_everyone(const struct nfs4ace *ace);

static inline int nfs4ace_is_allow(const struct nfs4ace *ace)
{
	return ace->e_type == ACE4_ACCESS_ALLOWED_ACE_TYPE;
}

static inline int nfs4ace_is_deny(const struct nfs4ace *ace)
{
	return ace->e_type == ACE4_ACCESS_DENIED_ACE_TYPE;
}

extern const char *nfs4ace_get_who(const struct nfs4ace *ace);

extern int nfs4ace_set_who(struct nfs4ace *, const char *);
extern void nfs4ace_set_uid(struct nfs4ace *ace, uid_t uid);
extern void nfs4ace_set_gid(struct nfs4ace *ace, gid_t gid);

extern struct nfs4acl *nfs4acl_get_file(const char *);
extern struct nfs4acl *nfs4acl_get_fd(int);
extern int nfs4acl_set_file(const char *, const struct nfs4acl *);
extern int nfs4acl_set_fd(int, const struct nfs4acl *);

extern char *nfs4acl_to_text(const struct nfs4acl *, int);
extern struct nfs4acl *nfs4acl_from_text(const char *, void (*)(const char *, ...));

extern struct nfs4acl *nfs4acl_alloc(size_t);
extern struct nfs4acl *nfs4acl_clone(struct nfs4acl *);
extern void nfs4acl_free(struct nfs4acl *);

extern int nfs4acl_apply_masks(struct nfs4acl **);
extern void nfs4acl_compute_max_masks(struct nfs4acl *);
extern struct nfs4acl *nfs4acl_from_mode(mode_t);

#endif  /* __NFS4ACL_H */
