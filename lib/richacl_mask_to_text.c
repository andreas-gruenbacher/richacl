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

#include <errno.h>
#include <stdlib.h>
#include "sys/richacl.h"
#include "richacl-internal.h"
#include "string_buffer.h"

char *richacl_mask_to_text(unsigned int mask, int fmt)
{
	struct string_buffer *buffer;
	char *str = NULL;

	buffer = alloc_string_buffer(16);
	if (!buffer)
		return NULL;
	write_mask(buffer, mask, fmt);

	if (string_buffer_okay(buffer)) {
		str = realloc(buffer->buffer, buffer->offset + 1);
		if (str)
			buffer->buffer = NULL;
	} else
		errno = ENOMEM;
	free_string_buffer(buffer);
	return str;
}
