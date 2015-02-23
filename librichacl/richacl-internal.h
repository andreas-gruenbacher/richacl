/*
  Copyright (C) 2006, 2009, 2010  Novell, Inc.
  Written by Andreas Gruenbacher <agruen@suse.de>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __RICHACL_INTERNAL_H
#define __RICHACL_INTERNAL_H

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#ifndef MAY_READ
# define MAY_READ S_IROTH
#endif

#ifndef MAY_WRITE
# define MAY_WRITE S_IWOTH
#endif

#ifndef MAY_EXEC
# define MAY_EXEC S_IXOTH
#endif

#ifndef S_IRWXUGO
# define S_IRWXUGO (S_IRWXU|S_IRWXG|S_IRWXO)
#endif

static inline void
richace_clear_inheritance_flags(struct richace *ace)
{
	ace->e_flags &= ~(ACE4_FILE_INHERIT_ACE |
			  ACE4_DIRECTORY_INHERIT_ACE |
			  ACE4_NO_PROPAGATE_INHERIT_ACE |
			  ACE4_INHERIT_ONLY_ACE |
			  ACE4_INHERITED_ACE);
}

extern const char *richace_owner_who;
extern const char *richace_group_who;
extern const char *richace_everyone_who;

#endif  /* __RICHACL_INTERNAL_H */
