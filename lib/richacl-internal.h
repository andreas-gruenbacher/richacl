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

static inline void
richace_clear_inheritance_flags(struct richace *ace)
{
	ace->e_flags &= ~(RICHACE_FILE_INHERIT_ACE |
			  RICHACE_DIRECTORY_INHERIT_ACE |
			  RICHACE_NO_PROPAGATE_INHERIT_ACE |
			  RICHACE_INHERIT_ONLY_ACE |
			  RICHACE_INHERITED_ACE);
}

extern const char *richace_owner_who;
extern const char *richace_group_who;
extern const char *richace_everyone_who;

#endif  /* __RICHACL_INTERNAL_H */
