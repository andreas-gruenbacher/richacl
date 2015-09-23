/*
  Copyright (C) 2006, 2009, 2010  Novell, Inc.
  Copyright (C) 2015  Red Hat, Inc.
  Written by Andreas Gruenbacher <agruenba@redhat.com>

  The richacl library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  The richacl library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see
  <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include "richacl.h"
#include "richacl-internal.h"

/**
 * struct richacl_alloc  -  remember how many entries are actually allocated
 * @acl:	acl with a_count <= @count
 * @count:	the actual number of entries allocated in @acl
 *
 * We pass around this structure while modifying an acl, so that we do
 * not have to reallocate when we remove existing entries followed by
 * adding new entries.
 */
struct richacl_alloc {
	struct richacl *acl;
	unsigned int count;
};

/**
 * richacl_delete_entry  -  delete an entry in an acl
 * @alloc:	acl and number of allocated entries
 * @ace:	an entry in @alloc->acl
 *
 * Updates @ace so that it points to the entry before the deleted entry
 * on return. (When deleting the first entry, @ace will point to the
 * (non-existant) entry before the first entry). This behavior is the
 * expected behavior when deleting entries while forward iterating over
 * an acl.
 */
static void
richacl_delete_entry(struct richacl_alloc *alloc, struct richace **ace)
{
	void *end = alloc->acl->a_entries + alloc->acl->a_count;

	memmove(*ace, *ace + 1, end - (void *)(*ace + 1));
	(*ace)--;
	alloc->acl->a_count--;
}

/**
 * richacl_insert_entry  -  insert an entry in an acl
 * @alloc:	acl and number of allocated entries
 * @ace:	entry before which the new entry shall be inserted
 *
 * Insert a new entry in @alloc->acl at position @ace, and zero-initialize
 * it.  This may require reallocating @alloc->acl.
 */
static int
richacl_insert_entry(struct richacl_alloc *alloc, struct richace **ace)
{
	int n = *ace - alloc->acl->a_entries;

	if (alloc->count == alloc->acl->a_count) {
		size_t size = sizeof(struct richacl) +
			      (alloc->count + 1) * sizeof(struct richace);
		struct richacl *acl2;

		acl2 = realloc(alloc->acl, size);
		if (!acl2)
			return -1;
		alloc->count++;
		alloc->acl = acl2;
		*ace = acl2->a_entries + n;
	}
	memmove(*ace + 1, *ace, sizeof(struct richace) * (alloc->acl->a_count - n));
	memset(*ace, 0, sizeof(struct richace));
	alloc->acl->a_count++;
	return 0;
}

/**
 * richacl_append_entry  -  append an entry to an acl
 * @alloc:	acl and number of allocated entries
 *
 * Append a new entry to @alloc->acl and zero-initialize it.
 * This may require reallocating @alloc->acl.
 */
static struct richace *
richacl_append_entry(struct richacl_alloc *alloc)
{
	struct richace *ace;

	if (alloc->count == alloc->acl->a_count) {
		size_t size = sizeof(struct richacl) +
			      (alloc->count + 1) * sizeof(struct richace);
		struct richacl *acl2;

		acl2 = realloc(alloc->acl, size);
		if (!acl2)
			return NULL;
		alloc->count++;
		alloc->acl = acl2;
	}
	ace = alloc->acl->a_entries + alloc->acl->a_count;
	alloc->acl->a_count++;
	memset(ace, 0, sizeof(struct richace));
	return ace;
}

/**
 * richace_change_mask  -  change the mask in @ace to @mask
 * @alloc:	acl and number of allocated entries
 * @ace:	entry to modify
 * @mask:	new mask for @ace
 *
 * Set the effective mask of @ace to @mask. This will require splitting
 * off a separate acl entry if @ace is inheritable. In that case, the
 * effective- only acl entry is inserted after the inheritable acl
 * entry, end the inheritable acl entry is set to inheritable-only. If
 * @mode is 0, either set the original acl entry to inheritable-only if
 * it was inheritable, or remove it otherwise.  The returned @ace points
 * to the modified or inserted effective-only acl entry if that entry
 * exists, to the entry that has become inheritable-only, or else to the
 * previous entry in the acl. This is the expected behavior when
 * modifying masks while forward iterating over an acl.
 */
static int
richace_change_mask(struct richacl_alloc *alloc, struct richace **ace,
			   unsigned int mask)
{
	if (mask && (*ace)->e_mask == mask)
		(*ace)->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
	else if (mask & ~RICHACE_POSIX_ALWAYS_ALLOWED) {
		if (richace_is_inheritable(*ace)) {
			if (richacl_insert_entry(alloc, ace))
				return -1;
			if (richace_copy(*ace, *ace + 1))
				return -1;
			(*ace)->e_flags |= RICHACE_INHERIT_ONLY_ACE;
			(*ace)++;
			richace_clear_inheritance_flags(*ace);
		}
		(*ace)->e_mask = mask;
	} else {
		if (richace_is_inheritable(*ace))
			(*ace)->e_flags |= RICHACE_INHERIT_ONLY_ACE;
		else
			richacl_delete_entry(alloc, ace);
	}
	return 0;
}

/**
 * richacl_move_everyone_aces_down  -  move everyone@ acl entries to the end
 * @alloc:	acl and number of allocated entries
 *
 * Move all everyone acl entries to the bottom of the acl so that only a
 * single everyone@ allow acl entry remains at the end, and update the
 * mask fields of all acl entries on the way. If everyone@ is not
 * granted any permissions, no empty everyone@ acl entry is inserted.
 *
 * This transformation does not modify the permissions that the acl
 * grants, but simplifies successive transformations.
 */
static int
richacl_move_everyone_aces_down(struct richacl_alloc *alloc)
{
	struct richace *ace;
	unsigned int allowed = 0, denied = 0;

	richacl_for_each_entry(ace, alloc->acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				allowed |= (ace->e_mask & ~denied);
			else if (richace_is_deny(ace))
				denied |= (ace->e_mask & ~allowed);
			else
				continue;
			if (richace_change_mask(alloc, &ace, 0))
				return -1;
		} else {
			if (richace_is_allow(ace)) {
				if (richace_change_mask(alloc, &ace, allowed |
						(ace->e_mask & ~denied)))
					return -1;
			} else if (richace_is_deny(ace)) {
				if (richace_change_mask(alloc, &ace, denied |
						(ace->e_mask & ~allowed)))
					return -1;
			}
		}
	}
	if (allowed & ~RICHACE_POSIX_ALWAYS_ALLOWED) {
		struct richace *last_ace = ace - 1;

		if (alloc->acl->a_count &&
		    richace_is_everyone(last_ace) &&
		    richace_is_allow(last_ace) &&
		    richace_is_inherit_only(last_ace) &&
		    last_ace->e_mask == allowed)
			last_ace->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
		else {
			if (richacl_insert_entry(alloc, &ace))
				return -1;
			ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
			ace->e_flags = RICHACE_SPECIAL_WHO;
			ace->e_mask = allowed;
			ace->e_id = RICHACE_EVERYONE_SPECIAL_ID;
		}
	}
	return 0;
}

/*
 * __richacl_propagate_everyone  -  propagate everyone@ permissions up for @who
 * @alloc:	acl and number of allocated entries
 * @who:	identifier to propagate permissions for
 * @allow:	permissions to propagate up
 *
 * Propagate the permissions in @allow up from the end of the acl to the start
 * for the specified principal @who.
 *
 * The simplest possible approach to achieve this would be to insert a
 * "<who>:<allow>::allow" ace before the final everyone@ allow ace.  Since this
 * would often result in aces which are not needed or which could be merged
 * with existing aces, we make the following optimizations:
 *
 *   - We go through the acl and determine which permissions are already
 *     allowed or denied to @who, and we remove those permissions from
 *     @allow.
 *
 *   - If the acl contains an allow ace for @who and no aces after this entry
 *     deny permissions in @allow, we add the permissions in @allow to this
 *     ace.  (Propagating permissions across a deny ace which could match the
 *     process could elevate permissions.)
 *
 * This transformation does not alter the permissions that the acl grants.
 */
static int
__richacl_propagate_everyone(struct richacl_alloc *alloc, struct richace *who,
			     unsigned int allow)
{
	struct richace *allow_last = NULL, *ace;
	struct richacl *acl = alloc->acl;

	/*
	 * Remove the permissions from allow that are already determined for
	 * this who value, and figure out if there is an allow entry for
	 * this who value that is "reachable" from the trailing everyone@
	 * allow ace
	 */
	richacl_for_each_entry(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_allow(ace)) {
			if (richace_is_same_identifier(ace, who)) {
				allow &= ~ace->e_mask;
				allow_last = ace;
			}
		} else if (richace_is_deny(ace)) {
			if (richace_is_same_identifier(ace, who))
				allow &= ~ace->e_mask;
			else if (allow & ace->e_mask)
				allow_last = NULL;
		}
	}
	ace--;

	/*
	 * If for group class entries, all the remaining permissions will
	 * remain granted by the trailing everyone@ allow ace, no additional
	 * entry is needed.
	 */
	if (!richace_is_owner(who) &&
	    richace_is_everyone(ace) &&
	    !(allow & ~(ace->e_mask & acl->a_other_mask)))
		allow = 0;

	if (allow) {
		if (allow_last)
			return richace_change_mask(alloc, &allow_last,
						   allow_last->e_mask | allow);
		else {
			struct richace who_copy = {};

			if (richace_copy(&who_copy, who))
				return -1;
			if (richacl_insert_entry(alloc, &ace))
				return -1;
			if (richace_copy(ace, &who_copy)) {
				richace_free(&who_copy);
				return -1;
			}
			richace_free(&who_copy);
			ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
			richace_clear_inheritance_flags(ace);
			ace->e_mask = allow;
		}
	}
	return 0;
}

/**
 * richacl_propagate_everyone  -  propagate everyone@ mask flags up the acl
 * @alloc:	acl and number of allocated entries
 *
 * Make sure that group@ and all other users and groups mentioned in the acl
 * will not lose any permissions when finally applying the other mask to the
 * everyone@ allow ace at the end of the acl.  We modify the permissions of
 * existing entries or add new entries before the final everyone@ allow ace to
 * achieve that.
 *
 * For example, the following acl implicitly grants everyone rwpx access:
 *
 *    joe:r::allow
 *    everyone@:rwpx::allow
 *
 * When applying mode 0660 to this acl, group@ would lose rwp access, and joe
 * would lose wp access even though the mode does not exclude those
 * permissions.  After propagating the everyone@ permissions, the result for
 * applying mode 0660 becomes:
 *
 *    owner@:rwp::allow
 *    joe:rwp::allow
 *    group@:rwp::allow
 *
 * Deny aces complicate the matter.  For example, the following acl grants
 * everyone but joe write access:
 *
 *    joe:wp::deny
 *    everyone@:rwpx::allow
 *
 * When applying mode 0660 to this acl, group@ would lose rwp access, and joe
 * would lose r access.  After propagating the everyone@ permissions, the
 * result for applying mode 0660 becomes:
 *
 *    owner@:rwp::allow
 *    joe:w::deny
 *    group@:rwp::allow
 *    joe:r::allow
 */
static int
richacl_propagate_everyone(struct richacl_alloc *alloc)
{
	struct richace who = { .e_flags = RICHACE_SPECIAL_WHO };
	struct richacl *acl = alloc->acl;
	struct richace *ace;
	unsigned int owner_allow, group_allow;

	if (!acl->a_count)
		return 0;
	ace = acl->a_entries + acl->a_count - 1;
	if (richace_is_inherit_only(ace) || !richace_is_everyone(ace))
		return 0;

	/*
	 * Permissions the owner and group class are granted through the
	 * trailing everyone@ allow ace.
	 */
	owner_allow = ace->e_mask & acl->a_owner_mask;
	group_allow = ace->e_mask & acl->a_group_mask;

	/*
	 * If the group or other masks hide permissions which the owner should
	 * be allowed, we need to propagate those permissions up.  Otherwise,
	 * those permissions may be lost when applying the other mask to the
	 * trailing everyone@ allow ace, or when isolating the group class from
	 * the other class through additional deny aces.
	 */
	if (owner_allow & ~(acl->a_group_mask & acl->a_other_mask)) {
		/* Propagate everyone@ permissions through to owner@. */
		who.e_id = RICHACE_OWNER_SPECIAL_ID;
		if (__richacl_propagate_everyone(alloc, &who, owner_allow))
			return -1;
		acl = alloc->acl;
	}

	/*
	 * If the other mask hides permissions which the group class should be
	 * allowed, we need to propagate those permissions up to the owning
	 * group and to all other members in the group class.
	 */
	if (group_allow & ~acl->a_other_mask) {
		int n;

		/* Propagate everyone@ permissions through to group@. */
		who.e_id = RICHACE_GROUP_SPECIAL_ID;
		if (__richacl_propagate_everyone(alloc, &who, group_allow))
			return -1;
		acl = alloc->acl;

		/* Start from the entry before the trailing everyone@ allow
		   entry. We will not hit everyone@ entries in the loop. */
		for (n = acl->a_count - 2; n != -1; n--) {
			ace = acl->a_entries + n;

			if (richace_is_inherit_only(ace) ||
			    richace_is_owner(ace) ||
			    richace_is_group(ace))
				continue;

			/*
			 * Any inserted entry will end up below the current
			 * entry.
			 */
			if (__richacl_propagate_everyone(alloc, ace, group_allow))
				return -1;
			acl = alloc->acl;
		}
	}
	return 0;
}

/**
 * __richacl_apply_masks  -  apply the masks to the acl entries
 * @alloc:	acl and number of allocated entries
 * @owner:	the file owner the acl belongs to
 *
 * Apply the owner file mask to owner@ entries and entries matching the owner
 * uid, the other file mask to everyone@ entries, and the group file mask to
 * all other entries.
 */
static int
__richacl_apply_masks(struct richacl_alloc *alloc, uid_t owner)
{
	struct richace *ace;

	richacl_for_each_entry(ace, alloc->acl) {
		unsigned int mask;

		if (richace_is_inherit_only(ace) || !richace_is_allow(ace))
			continue;
		if (richace_is_owner(ace) ||
		    (richace_is_unix_user(ace) && ace->e_id == owner))
			mask = alloc->acl->a_owner_mask;
		else if (richace_is_everyone(ace))
			mask = alloc->acl->a_other_mask;
		else
			mask = alloc->acl->a_group_mask;
		if (richace_change_mask(alloc, &ace, ace->e_mask & mask))
			return -1;
	}
	return 0;
}

/**
 * richacl_max_allowed  -  maximum mask flags that anybody is allowed
 */
static unsigned int
richacl_max_allowed(struct richacl *acl)
{
	struct richace *ace;
	unsigned int allowed = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_allow(ace))
			allowed |= ace->e_mask;
		else if (richace_is_deny(ace)) {
			if (richace_is_everyone(ace))
				allowed &= ~ace->e_mask;
		}
	}
	return allowed;
}

/**
 * richacl_isolate_owner_class  -  limit the owner class to the owner file mask
 * @alloc:	acl and number of allocated entries
 *
 * Make sure the owner class (owner@) is granted no more than the owner
 * mask by first checking which permissions anyone is granted, and then
 * denying owner@ all permissions beyond that.
 */
static int
richacl_isolate_owner_class(struct richacl_alloc *alloc)
{
	struct richacl *acl = alloc->acl;
	unsigned int deny = richacl_max_allowed(acl) & ~acl->a_owner_mask;

	if (deny) {
		struct richace *ace;

		/*
		 * Figure out if we can update an existig OWNER@ DENY entry.
		 */
		richacl_for_each_entry(ace, acl) {
			if (richace_is_inherit_only(ace))
				continue;
			if (richace_is_allow(ace))
				break;
			if (richace_is_owner(ace)) {
				return richace_change_mask(alloc, &ace,
							   ace->e_mask | deny);
			}
		}

		/* Insert an owner@ deny entry at the front. */
		ace = acl->a_entries;
		if (richacl_insert_entry(alloc, &ace))
			return -1;
		ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = deny;
		ace->e_id = RICHACE_OWNER_SPECIAL_ID;
	}
	return 0;
}

/**
 * __richacl_isolate_who  -  isolate entry from everyone@ allow entry
 * @alloc:	acl and number of allocated entries
 * @who:	identifier to isolate
 * @deny:	permissions this identifier should not be allowed
 *
 * See richacl_isolate_group_class().
 */
static int
__richacl_isolate_who(struct richacl_alloc *alloc, struct richace *who,
		      unsigned int deny)
{
	struct richacl *acl = alloc->acl;
	struct richace *ace, who_copy = { };
	int n;

	/*
	 * Compute the permissions already denied to @who.
	 */
	richacl_for_each_entry(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_same_identifier(ace, who) &&
		    richace_is_deny(ace))
			deny &= ~ace->e_mask;
	}
	if (!deny)
		return 0;

	/*
	 * Figure out if we can update an existig deny entry.  Start from the
	 * entry before the trailing everyone@ allow entry. We will not hit
	 * everyone@ entries in the loop.
	 */
	for (n = acl->a_count - 2; n != -1; n--) {
		ace = acl->a_entries + n;
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_deny(ace)) {
			if (richace_is_same_identifier(ace, who))
				return richace_change_mask(alloc, &ace,
							   ace->e_mask | deny);
		} else if (richace_is_allow(ace) &&
			   (ace->e_mask & deny))
			break;
	}

	/*
	 * Insert a new entry before the trailing everyone@ deny entry.
	 */
	if (richace_copy(&who_copy, who))
		return -1;
	ace = acl->a_entries + acl->a_count - 1;
	if (richacl_insert_entry(alloc, &ace))
		return -1;
	if (richace_copy(ace, &who_copy)) {
		richace_free(&who_copy);
		return -1;
	}
	richace_free(&who_copy);
	ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
	richace_clear_inheritance_flags(ace);
	ace->e_mask = deny;
	return 0;
}

/**
 * richacl_isolate_group_class  -  limit the group class to the group file mask
 * @alloc:	acl and number of allocated entries
 *
 * Make sure the group class (all entries except owner@ and everyone@) is
 * granted no more than the group mask by inserting deny entries for group
 * class entries where necessary.
 */
static int
richacl_isolate_group_class(struct richacl_alloc *alloc)
{
	struct richace who = {
		.e_flags = RICHACE_SPECIAL_WHO,
		.e_id = RICHACE_GROUP_SPECIAL_ID,
	};
	struct richace *ace;
	unsigned int deny;

	if (!alloc->acl->a_count)
		return 0;
	ace = alloc->acl->a_entries + alloc->acl->a_count - 1;
	if (richace_is_inherit_only(ace) || !richace_is_everyone(ace))
		return 0;
	deny = ace->e_mask & ~alloc->acl->a_group_mask;

	if (deny) {
		unsigned int n;

		if (__richacl_isolate_who(alloc, &who, deny))
			return -1;

		/*
		 * Start from the entry before the trailing everyone@ allow
		 * entry.  We will not hit everyone@ entries in the loop.
		 */
		for (n = alloc->acl->a_count - 2; n != -1; n--) {
			ace = alloc->acl->a_entries + n;

			if (richace_is_inherit_only(ace) ||
			    richace_is_owner(ace) ||
			    richace_is_group(ace))
				continue;
			if (__richacl_isolate_who(alloc, ace, deny))
				return -1;
		}
	}
	return 0;
}

/**
 * richacl_set_owner_permissions  -  set the owner permissions to the owner mask
 */
static int
richacl_set_owner_permissions(struct richacl_alloc *alloc)
{
	unsigned int x = RICHACE_POSIX_ALWAYS_ALLOWED;
	unsigned int owner_mask = alloc->acl->a_owner_mask & ~x;
	unsigned int denied = 0;
	struct richace *ace;

	if (!((alloc->acl->a_flags & RICHACL_WRITE_THROUGH) &&
	      (alloc->acl->a_flags & RICHACL_MASKED)))
		return 0;

	richacl_for_each_entry(ace, alloc->acl) {
		if (richace_is_owner(ace)) {
			if (richace_is_allow(ace) && !(owner_mask & denied)) {
				richace_change_mask(alloc, &ace, owner_mask);
				owner_mask = 0;
			} else
				richace_change_mask(alloc, &ace, 0);
		} else {
			if (richace_is_deny(ace))
				denied |= ace->e_mask;
		}
	}

	if (owner_mask & (denied |
			  ~alloc->acl->a_other_mask |
			  ~alloc->acl->a_group_mask)) {
		ace = alloc->acl->a_entries;
		if (richacl_insert_entry(alloc, &ace))
			return -1;
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = owner_mask;
		ace->e_id = RICHACE_OWNER_SPECIAL_ID;
	}
	return 0;
}

/**
 * richacl_set_other_permissions  -  set the other permissions to the other mask
 */
static int
richacl_set_other_permissions(struct richacl_alloc *alloc)
{
	struct richacl *acl = alloc->acl;
	unsigned int x = RICHACE_POSIX_ALWAYS_ALLOWED;
	unsigned int other_mask = acl->a_other_mask & ~x;
	struct richace *ace = acl->a_entries + acl->a_count - 1;

	if (!(other_mask &&
	      (alloc->acl->a_flags & RICHACL_WRITE_THROUGH) &&
	      (alloc->acl->a_flags & RICHACL_MASKED)))
		return 0;

	if (acl->a_count == 0 ||
	    !richace_is_everyone(ace) ||
	    richace_is_inherit_only(ace)) {
		ace++;
		if (richacl_insert_entry(alloc, &ace))
			return -1;
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = other_mask;
		ace->e_id = RICHACE_EVERYONE_SPECIAL_ID;
	} else
		richace_change_mask(alloc, &ace, other_mask);
	return 0;
}

/**
 * richacl_apply_masks  -  apply the masks to the acl
 *
 * Apply the masks so that the acl allows no more flags than the
 * intersection between the flags that the original acl allows and the
 * mask matching the process.
 *
 * Note: this algorithm may push the number of entries in the acl above
 * RICHACL_XATTR_MAX_COUNT, so a read-modify-write cycle would fail.
 */
int
richacl_apply_masks(struct richacl **acl, uid_t owner)
{
	int retval = 0;

	if ((*acl)->a_flags & RICHACL_MASKED) {
		struct richacl_alloc alloc = {
			.acl = *acl,
			.count = (*acl)->a_count,
		};
		if (richacl_move_everyone_aces_down(&alloc) ||
		    richacl_propagate_everyone(&alloc) ||
		    __richacl_apply_masks(&alloc, owner) ||
		    richacl_set_owner_permissions(&alloc) ||
		    richacl_set_other_permissions(&alloc) ||
		    richacl_isolate_owner_class(&alloc) ||
		    richacl_isolate_group_class(&alloc))
				retval = -1;

		alloc.acl->a_flags &= ~(RICHACL_WRITE_THROUGH | RICHACL_MASKED);
		*acl = alloc.acl;
	}
	return retval;
}

struct richacl *
richacl_auto_inherit(const struct richacl *acl,
		     const struct richacl *inherited_acl)
{
	struct richacl_alloc alloc = {
		.acl = richacl_clone(acl),
		.count = acl->a_count,
	};
	const struct richace *inherited_ace;
	struct richace *ace;

	richacl_for_each_entry(ace, alloc.acl) {
		if (ace->e_flags & RICHACE_INHERITED_ACE)
			richacl_delete_entry(&alloc, &ace);
	}
	richacl_for_each_entry(inherited_ace, inherited_acl) {
		ace = richacl_append_entry(&alloc);
		if (!ace)
			return NULL;
		if (richace_copy(ace, inherited_ace)) {
			richacl_free(alloc.acl);
			return NULL;
		}
		ace->e_flags |= RICHACE_INHERITED_ACE;
	}
	return alloc.acl;
}
