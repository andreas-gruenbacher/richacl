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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "string_buffer.h"

struct string_buffer *alloc_string_buffer(size_t size)
{
	struct string_buffer *buffer = malloc(sizeof(struct string_buffer));

	if (buffer) {
		buffer->buffer = malloc(size);
		if (!buffer->buffer) {
			free(buffer);
			return NULL;
		}
		buffer->buffer[0] = 0;
		buffer->offset = 0;
		buffer->size = size;
	}

	return buffer;
}

void reset_string_buffer(struct string_buffer *buffer)
{
	buffer->buffer[0] = 0;
	buffer->offset = 0;
}

void free_string_buffer(struct string_buffer *buffer)
{
	if (buffer) {
		free(buffer->buffer);
		free(buffer);
	}
}

char *buffer_sprintf(struct string_buffer *buffer, const char *format, ...)
{
	va_list ap, aq;
	int needed;

	if (!string_buffer_okay(buffer))
		return NULL;

	va_start(ap, format);
	for(;;) {
		size_t new_size;
		char *new_buffer;

		va_copy(aq, ap);
		needed = vsnprintf(buffer->buffer + buffer->offset,
				   buffer->size - buffer->offset, format, aq);
		va_end(aq);
		if (needed < buffer->size - buffer->offset)
			break;

		new_size = buffer->size * 2;
		if (new_size < buffer->offset + needed + 1)
			new_size = buffer->offset + needed + 1;
		new_buffer = realloc(buffer->buffer, new_size);
		if (!new_buffer) {
			free(buffer->buffer);
			buffer->buffer = NULL;
			goto out;
		}

		buffer->buffer = new_buffer;
		buffer->size = new_size;
	}
	buffer->offset += needed;
out:
	va_end(ap);
	return buffer->buffer;
}
