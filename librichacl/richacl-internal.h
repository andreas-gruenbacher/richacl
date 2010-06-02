#ifndef __RICHACL_INTERNAL_H
#define __RICHACL_INTERNAL_H

/*
 * The ACE4_READ_ATTRIBUTES and ACE4_READ_ACL flags are always granted
 * in POSIX. The ACE4_SYNCHRONIZE flag has no meaning under POSIX.
 */
#define ACE4_POSIX_ALWAYS_ALLOWED ( \
	ACE4_SYNCHRONIZE | \
	ACE4_READ_ATTRIBUTES | \
	ACE4_READ_ACL )

/* e_flags bitflags */
#define ACE4_SPECIAL_WHO		0x4000  /* internal to the library */

static inline void
richace_clear_inheritance_flags(struct richace *ace)
{
	ace->e_flags &= ~(ACE4_FILE_INHERIT_ACE |
			  ACE4_DIRECTORY_INHERIT_ACE |
			  ACE4_NO_PROPAGATE_INHERIT_ACE |
			  ACE4_INHERIT_ONLY_ACE);
}

static inline int richace_is_inheritable(const struct richace *ace)
{
	return ace->e_flags & (ACE4_FILE_INHERIT_ACE |
			       ACE4_DIRECTORY_INHERIT_ACE);
}

static inline int richace_is_inherit_only(const struct richace *ace)
{
	return ace->e_flags & ACE4_INHERIT_ONLY_ACE;
}

extern const char *richace_owner_who;
extern const char *richace_group_who;
extern const char *richace_everyone_who;

#endif  /* __RICHACL_INTERNAL_H */
