/** @file
 **/
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <openssl/sha.h>

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

/* hashFile: wrapper for hashing a file
	@input fileHandle: an opened file handle
	@output digest: the calculated digest
*/

EFI_STATUS
hashFile(EFI_FILE_PROTOCOL *fileHandle, unsigned char *digest)
{
	char buffer[32];
	UINTN readlen;
	SHA256_CTX ctx;
	EFI_STATUS Status;

	SHA256_Init(&ctx);
	while (1) {
		readlen = 32;
		Status = fileHandle->Read(fileHandle, &readlen, buffer);
		if (EFI_ERROR(Status)) {
			Print(L"Read file error!\n");
			return Status;
		}
		if (readlen==0) {
			break;
		}
		SHA256_Update(&ctx, (const void*)buffer, readlen);
	}
	SHA256_Final(digest, &ctx);
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE           ImageHandle,
	IN EFI_SYSTEM_TABLE     *SystemTable
	)
{
    EFI_FILE_PROTOCOL *Root;
	 EFI_FILE_PROTOCOL *fileHandle;
	 unsigned char sha256digest[32];

    EFI_STATUS  Status;
	 int i;

    Status = GetFileIo(&Root);
	 if (!EFI_ERROR(Status)) {
		 Print(L"Successfully open root directory.\n");
	 } else {
		 Print(L"Open root directory failed.\n");
		 goto Error;
	 }

	 Root->Open(Root, &fileHandle, (CHAR16*)L"readme.txt", EFI_FILE_MODE_READ, 0);

	 if (!EFI_ERROR(Status)) {
		 Print(L"Successfully open readme.txt.\n");
	 } else {
		 Print(L"Open readme.txt failed.\n");
		 goto Error;
	 }

	 Status = hashFile(fileHandle, sha256digest);
	 if (!EFI_ERROR(Status)) {
		 for (i=0; i<32; i++) {
			 Print(L"%02x", sha256digest[i]);
		 }
		 Print(L"\n");
	 } else {
		 Print(L"Hash file error!\n");
		 goto Error;
	 }

	 while(1);
    return EFI_SUCCESS;
Error:
	 while(1);
	 return Status;
}
