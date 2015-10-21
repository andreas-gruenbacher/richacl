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

#include <string.h>
#include "sys/richacl.h"

bool richace_is_same_identifier(const struct richace *ace1,
				const struct richace *ace2)
{
	return !((ace1->e_flags ^ ace2->e_flags) &
		 (RICHACE_SPECIAL_WHO |
		  RICHACE_IDENTIFIER_GROUP |
		  RICHACE_UNMAPPED_WHO)) &&
	       ((ace1->e_flags & RICHACE_UNMAPPED_WHO) ?
	        !strcmp(ace1->e_who, ace2->e_who) :
		ace1->e_id == ace2->e_id);
}
