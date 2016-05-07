#include <stdio.h>
#include "iobuffer.h"

static int
ioread(struct IO_buffer *buf)
{
	FILE *f = (FILE*)(buf->handle);
	return fread(buf->buffer, 1, 4096, f);
}

static int
ioeof(struct IO_buffer *buf)
{
	FILE *f = (FILE*)(buf->handle);
	return feof(f);
}

static int
ioclose(struct IO_buffer *buf)
{
	FILE *f = (FILE*)(buf->handle);
	return fclose(f);
}

struct IO_buffer c_file_buffer = {
	.ioread = ioread,
	.ioeof = ioeof,
	.ioclose = ioclose
};
