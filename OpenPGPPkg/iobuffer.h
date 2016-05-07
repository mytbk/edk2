#pragma once

struct IO_buffer {
	void *handle;
	unsigned long filesize; /* should be set if using UEFI file */
	unsigned char *buffer; /* should be allocated by user */
	int (*ioread)(struct IO_buffer*);
	int (*ioeof)(struct IO_buffer*);
	int (*ioclose)(struct IO_buffer*);
};

extern struct IO_buffer c_file_buffer;
extern struct IO_buffer uefi_file_buffer;
