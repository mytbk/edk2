#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include "iobuffer.h"

static int
ioread(struct IO_buffer *buf)
{
	UINTN readlen;
	EFI_FILE_PROTOCOL *f = (EFI_FILE_PROTOCOL*)(buf->handle);
	EFI_STATUS status;

	status = f->Read(f, &readlen, buf->buffer);
	if (EFI_ERROR(status)) {
		Print(L"Read file error, status = %d\n", status);
		return -1;
	}
	return readlen;
}

static int
ioeof(struct IO_buffer *buf)
{
	unsigned long long pos;
	EFI_FILE_PROTOCOL *f = (EFI_FILE_PROTOCOL*)(buf->handle);
	f->GetPosition(f, &pos);
	return (pos==buf->filesize);
}

static int
ioclose(struct IO_buffer *buf)
{
	EFI_FILE_PROTOCOL *f = (EFI_FILE_PROTOCOL*)(buf->handle);
	return (f->Close(f)==0);
}

struct IO_buffer uefi_file_buffer = {
	.ioread = ioread,
	.ioeof = ioeof,
	.ioclose = ioclose
};
