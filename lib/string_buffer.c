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
	va_copy(aq, ap);
	for(;;) {
		size_t new_size;
		char *new_buffer;

		needed = vsnprintf(buffer->buffer + buffer->offset,
				   buffer->size - buffer->offset, format, ap);
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
	va_end(aq);
	va_end(ap);
out:
	return buffer->buffer;
}
