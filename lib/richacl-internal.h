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

#ifndef __RICHACL_INTERNAL_H
#define __RICHACL_INTERNAL_H

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

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

extern const char *richace_owner_who;
extern const char *richace_group_who;
extern const char *richace_everyone_who;

extern void richace_free(struct richace *);
extern unsigned int richacl_mode_to_mask(mode_t);
extern int in_groups(gid_t, const gid_t[], int);
extern int richacl_mask_to_mode(unsigned int);

extern void richacl_delete_entry(struct richacl_alloc *, struct richace **);
extern int richacl_insert_entry(struct richacl_alloc *, struct richace **);
extern struct richace *richacl_append_entry(struct richacl_alloc *);
extern int richace_change_mask(struct richacl_alloc *, struct richace **, unsigned int);

struct string_buffer;
extern void write_mask(struct string_buffer *, unsigned int, int);

struct richacl_flag_bit {
	char		a_char;
	unsigned char	a_flag;
	const char	*a_name;
};
extern const struct richacl_flag_bit acl_flag_bits[];
extern const unsigned int acl_flag_bits_size;

struct richacl_type_value {
	unsigned short	e_type;
	const char	*e_name;
};
extern const struct richacl_type_value type_values[];
extern const unsigned int type_values_size;

struct richace_flag_bit {
	unsigned short	e_flag;
	char		e_char;
	const char	*e_name;
};
extern const struct richace_flag_bit ace_flag_bits[];
extern const unsigned int ace_flag_bits_size;

struct richacl_mask_flag {
	unsigned int	e_mask;
	char		e_char;
	const char	*e_name;
	int		e_context;
};
extern const struct richacl_mask_flag mask_flags[];
extern const unsigned int mask_flags_size;

#endif  /* __RICHACL_INTERNAL_H */
