#ifndef __STRING_BUFFER_H
#define __STRING_BUFFER_H

#include <sys/types.h>

/* A resizeable string buffer */
struct string_buffer {
	char *buffer;
	size_t offset;
	size_t size;
};

extern struct string_buffer *alloc_string_buffer(size_t size);
extern void reset_string_buffer(struct string_buffer *);
extern void free_string_buffer(struct string_buffer *);
extern char *buffer_sprintf(struct string_buffer *, const char *, ...)
	__attribute__((format (printf, 2, 3)));

static inline int string_buffer_okay(const struct string_buffer *buffer)
{
	return !!buffer->buffer;
}

#endif  /* __STRING_BUFFER_H */
