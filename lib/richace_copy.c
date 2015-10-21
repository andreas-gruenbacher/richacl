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
#include <string.h>
#include "sys/richacl.h"

int richace_copy(struct richace *dst, const struct richace *src)
{
	char *who = src->e_who;

	if (src->e_flags & RICHACE_UNMAPPED_WHO) {
		who = strdup(who);
		if (!who)
			return -1;
	}
	if (dst->e_flags & RICHACE_UNMAPPED_WHO)
		free(dst->e_who);
	memcpy(dst, src, sizeof(struct richace));
	dst->e_who = who;
	return 0;
}
