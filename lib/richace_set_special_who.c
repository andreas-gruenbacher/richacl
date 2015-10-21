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
#include "richacl-internal.h"

const char *richace_owner_who	 = "OWNER@";
const char *richace_group_who	 = "GROUP@";
const char *richace_everyone_who = "EVERYONE@";

int richace_set_special_who(struct richace *ace, const char *who)
{
	int id;

	if (!strcmp(who, richace_owner_who))
		id = RICHACE_OWNER_SPECIAL_ID;
	else if (!strcmp(who, richace_group_who))
		id = RICHACE_GROUP_SPECIAL_ID;
	else if (!strcmp(who, richace_everyone_who))
		id = RICHACE_EVERYONE_SPECIAL_ID;
	else
		return -1;

	ace->e_id = id;
	ace->e_flags |= RICHACE_SPECIAL_WHO;
	/*
	 * Also clear the RICHACE_IDENTIFIER_GROUP flag for ACEs with a special
	 * who value: richace_is_same_identifier() relies on that.
	 */
	ace->e_flags &= ~(RICHACE_IDENTIFIER_GROUP |
			  RICHACE_UNMAPPED_WHO);
	return 0;
}
