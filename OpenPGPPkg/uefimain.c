#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include "cryptodata.h"

EFI_STATUS
GetFileIo( EFI_FILE_PROTOCOL** Root)
{
	 EFI_STATUS  Status = 0;
	 EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
	 Status = gBS->LocateProtocol(
		 &gEfiSimpleFileSystemProtocolGuid,
		 NULL,
		 (VOID**)&SimpleFileSystem
		 );
	 if (EFI_ERROR(Status)) {
		 return Status;
	 }
	 Status = SimpleFileSystem->OpenVolume(SimpleFileSystem, Root);
	 return Status;
}

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE           ImageHandle,
	IN EFI_SYSTEM_TABLE     *SystemTable
)
{
	/* public key file: pubkey.gpg
		signature file: readme.sig
		data file: readme
	*/

	EFI_STATUS status;
	EFI_FILE_PROTOCOL *Root;
	EFI_FILE_PROTOCOL *fileHandle;
	EFI_FILE_INFO *fi;

	struct RSA_pubkey pubkey;
	struct parse_data sigdata;
	uint8_t buffer[4096];
	UINTN len;

	status = GetFileIo(&Root);
	if (EFI_ERROR(status)) {
		Print(L"Fail to open root directory.\n");
		return status;
	}

	/* open public key file */
	status = Root->Open(Root, &fileHandle, (CHAR16*)L"pubkey.gpg", EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(status)) {
		Print(L"Fail to open pubkey.gpg.\n");
		return status;
	}
	len = 4096;
	status = fileHandle->Read(fileHandle, &len, buffer);
	if (len==4096) {
		Print(L"File too big, not supported.\n");
		return 1;
	}
	if (parse_pubkey(buffer, &pubkey)<0) {
		Print(L"Parse public key packet error!\n");
		return 1;
	}
	fileHandle->Close(fileHandle);

	/* open signature file */
	status = Root->Open(Root, &fileHandle, (CHAR16*)L"readme.sig", EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(status)) {
		Print(L"Open signature file error!\n");
		return status;
	}
	len = 4096;
	status = fileHandle->Read(fileHandle, &len, buffer);
	if (len==4096) {
		Print(L"Signature file too large.\n");
		return 1;
	}
	if (parse_pgpdata(buffer, &sigdata)<0) {
		Print(L"Parse signature data error!\n");
		return 1;
	}
	fileHandle->Close(fileHandle);

	/* open data file and verify it */
	status = Root->Open(Root, &fileHandle, (CHAR16*)L"readme", EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(status)) {
		Print(L"Open data file error!\n");
		return status;
	}
	UINTN BufferSize = 1024;
	fi = (EFI_FILE_INFO*)AllocatePool(BufferSize);
	fileHandle->GetInfo(fileHandle, &gEfiFileInfoGuid, &BufferSize, (VOID*)fi);

	struct IO_buffer buf;
	buf.handle = (void*)fileHandle;
	buf.filesize = fi->FileSize;
	buf.buffer = buffer;
	buf.ioread = uefi_file_buffer.ioread;
	buf.ioeof = uefi_file_buffer.ioeof;
	buf.ioclose = uefi_file_buffer.ioclose;

	FreePool(fi);

	int result = pgpverify(&pubkey, &sigdata, &buf);
	if (result==1) {
		Print(L"verify success!\n");
	} else {
		Print(L"signature bad!\n");
	}

	return 0;
}
