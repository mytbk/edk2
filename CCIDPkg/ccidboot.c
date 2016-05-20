#include "ccid_oper.h"
#include <openpgp/cryptodata.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimpleTextInEx.h>
#include <Guid/FileInfo.h>
#include <openssl/sha.h>

#define ELINE -2
#define EFILE -1

#ifdef DEBUGPRN
#define DebugPrint Print
#else
#define DebugPrint(a,...) ;
#endif

#define TESTPATTERN0 "abcd1234" \
	"abcd1234" \
	"deadbeef" \
	"deadbeef"

static unsigned char *sha256digestinfo = (unsigned char*)
	"\x30\x31"
	"\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"
	"\x04\x20"
	TESTPATTERN0;

#define SHA256_DIGEST_INFO_LEN 51

static const char *charmap = "0123456789abcdef";
static const unsigned char *keyid = NULL;
static const unsigned char defaultfpr[] =
{0x9F, 0x42, 0x7E, 0xF3,
 0x09, 0xDE, 0x98, 0x56,
 0xAA, 0xB2, 0x09, 0xBB,
 0x99, 0xE7, 0xBD, 0x5A,
 0xD0, 0x51, 0xC1, 0x7B};
static CHAR16* pubkeyfile = L"xxxxxxxx.gpg";
static CHAR16* hashlist = L"xxxxxxxx.sha256sums";
static CHAR16* hashlistsig = L"xxxxxxxx.sha256sums.sig";
static unsigned char pubkeydata[1<<20];
static UINTN pubkeybuflen;
static struct RSA_pubkey rsakey;
static unsigned char sigmsgbuf[1024];
static unsigned int sigbuflen=0;
static UINTN readlen=0;
static EFI_FILE_PROTOCOL *Root;
static EFI_EVENT readytoboot;

static void
targetu16fn(CHAR16* fn)
{
	for (int i=0; i<4; i++) {
		fn[0] = charmap[keyid[i]>>4];
		fn[1] = charmap[keyid[i]&0xf];
		fn += 2;
	}
}

static EFI_STATUS
GetFileIo( EFI_FILE_PROTOCOL** Root)
{
	EFI_STATUS Status = 0;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
	Status = gBS->LocateProtocol(
		&gEfiSimpleFileSystemProtocolGuid,
		NULL,
		(VOID**)&SimpleFileSystem
		);
	if (EFI_ERROR(Status)) {
		AsciiPrint("EFI system partition not found!\n");
		return Status;
	}
	Status = SimpleFileSystem->OpenVolume(SimpleFileSystem, Root);
	if (EFI_ERROR(Status)) {
		AsciiPrint("Open EFI system partition failed, Status=%d\n", Status);
	}
	return Status;
}

void
GetString(unsigned char *str, UINTN *len)
{
	EFI_SIMPLE_TEXT_INPUT_PROTOCOL *conin = gST->ConIn;
	EFI_INPUT_KEY key = {.ScanCode=0, .UnicodeChar=0};
	*len = 0;

	while ((char)key.UnicodeChar!='\n' && (char)key.UnicodeChar!='\r') {
		EFI_STATUS Status = conin->ReadKeyStroke(conin, &key);
		if (Status==EFI_SUCCESS) {
			*str = key.UnicodeChar;
			*len = *len+1;
			str++;
		} else if (Status==EFI_DEVICE_ERROR) {
			return;
		}
	}
	*len = *len-1; // remove the carry/linefeed
}

static int
havekey(unsigned char fpr[])
{
	for (int i=0; i<20; i++) {
		if (fpr[i]!=0) {
			return 1;
		}
	}
	return 0;
}

EFI_STATUS
setkey_nocard()
{
	EFI_FILE_PROTOCOL *pubFileHandle;
	EFI_STATUS Status;

	keyid = defaultfpr+16;
	targetu16fn(pubkeyfile);
	targetu16fn(hashlistsig);
	targetu16fn(hashlist);

	pubkeybuflen = sizeof(pubkeydata);
	SAFECALLE(Status, Root->Open(Root, &pubFileHandle, pubkeyfile, EFI_FILE_MODE_READ, 0));
	SAFECALLE(Status, pubFileHandle->Read(pubFileHandle, &pubkeybuflen, pubkeydata));
	SAFECALLE(Status, pubFileHandle->Close(pubFileHandle));
	AsciiPrint("%d bytes read from public key file.\n", (int)pubkeybuflen);

	if (find_pubkey(pubkeydata, pubkeybuflen, &rsakey, defaultfpr+12)!=0) {
		AsciiPrint("Cannot find the public key of the OpenPGP card.\n");
		keyid = NULL;
		return EFI_ABORTED;
	}
	return EFI_SUCCESS;
}

EFI_STATUS
verify_signed_hashlist()
{
	EFI_STATUS status;
	EFI_FILE_PROTOCOL *fileHandle;
	EFI_FILE_INFO *fi;

	struct parse_data sigdata;
	uint8_t buffer[4096];
	UINTN len;

	targetu16fn(hashlistsig);
	targetu16fn(hashlist);

	/* open signature file */
	SAFECALLE(status, Root->Open(Root, &fileHandle, hashlistsig, EFI_FILE_MODE_READ, 0));
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
	SAFECALLE(status, Root->Open(Root, &fileHandle, hashlist, EFI_FILE_MODE_READ, 0));

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

	int result = pgpverify(&rsakey, &sigdata, &buf);
	FreePool(fi);

	if (result==1) {
		Print(L"verify success!\n");
		return EFI_SUCCESS;
	} else {
		Print(L"signature bad!\n");
		return EFI_ABORTED;
	}
}

static inline int
digitval(char a)
{
	if (a>='0' && a<='9') {
		return a-'0';
	}
	if (a>='a' && a<='f') {
		return a-'a'+10;
	}
	if (a>='A' && a<='F') {
		return a-'A'+10;
	}
	return -1;
}

/* read from a SHA256SUM file, format:
	<hash>  <filename>
*/
static int
read_name_hash_line(EFI_FILE_PROTOCOL *handle, CHAR16 *fn, uint8_t *digest)
{
	EFI_STATUS Status;
	UINTN readlen;
	char c;
	int val;

	/* read hash */
	for (int i=0; i<32; i++) {
		readlen = 1;
		Status = handle->Read(handle, &readlen, &c);
		if (EFI_ERROR(Status) || readlen==0) {
			return EFILE;
		}
		if (c=='\n') {
			return ELINE;
		}
		val = digitval(c);
		if (val==-1) {
			return ELINE;
		}
		digest[i] = val*16;

		readlen = 1;
		Status = handle->Read(handle, &readlen, &c);
		if (EFI_ERROR(Status) || readlen==0) {
			return EFILE;
		}
		if (c=='\n') {
			return ELINE;
		}
		val = digitval(c);
		if (val==-1) {
			return ELINE;
		}
		digest[i] += val;
	}

	DebugPrint(L"Hash read finished!\n");

	/* skip all spaces */
	do {
		readlen = 1;
		Status = handle->Read(handle, &readlen, &c);
		if (EFI_ERROR(Status) || readlen==0) {
			return EFILE;
		}
		if (c=='\n') {
			return ELINE;
		}
	} while(c==' ');

	DebugPrint(L"Spaces skipped.\n");

	if (c=='/') {
		*fn = '\\';
	} else {
		*fn = c;
	}
	fn++;
	while (1) {
		readlen = 1;
		Status = handle->Read(handle, &readlen, &c);
		if (EFI_ERROR(Status) || readlen==0) {
			return EFILE;
		}
		if (c=='\n') {
			*fn = 0;
			return 0;
		}
		if (c!=' ') {
			if (c=='/') {
				*fn = '\\';
			} else {
				*fn = c;
			}
			fn++;
		} else {
			*fn = 0;
			break;
		}
	}

	/* read the remaining of line */
	while (1) {
		readlen = 1;
		Status = handle->Read(handle, &readlen, &c);
		if (EFI_ERROR(Status) || readlen==0) {
			return EFILE;
		}
		if (c=='\n') {
			return 0;
		}
	}
}

/* hashFile: wrapper for hashing a file
	@input fileHandle: an opened file handle
	@output digest: the calculated digest
*/

static EFI_STATUS
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

static int
sha256cmp(const uint8_t *a, const uint8_t *b)
{
	for (int i=0; i<32; i++) {
		if (a[i]!=b[i]) {
			return a[i]-b[i];
		}
	}
	return 0;
}

EFI_STATUS
verify_hashes()
{
	EFI_STATUS Status;
	CHAR16 u16fn[1024];
	EFI_FILE_PROTOCOL *fileHandle;
	EFI_FILE_PROTOCOL *vfileHandle;
	unsigned char sha256digest[32];
	unsigned char sha256toverify[32];
	int err;

	SAFECALLE(Status, Root->Open(Root, &fileHandle, hashlist, EFI_FILE_MODE_READ, 0));

	while (1) {
		/* read each line of the file for filename and hash */
		err = read_name_hash_line(fileHandle, u16fn, sha256toverify);
		if (err==EFILE) {
			DebugPrint(L"End of file or error!\n");
			break;
		}
		if (err==ELINE) {
			DebugPrint(L"Line error occured.\n");
			continue;
		}
		if (err==0) {
			/* read the file (u16fn) and check the hash */
			DebugPrint(L"Opening %s\n", u16fn);
			Status = Root->Open(Root, &vfileHandle, u16fn, EFI_FILE_MODE_READ, 0);
			if (EFI_ERROR(Status)) {
				DebugPrint(L"Open file %s error!\n", u16fn);
				return EFI_ABORTED;
			}
			SAFECALLE(Status, hashFile(vfileHandle, sha256digest));
			vfileHandle->Close(vfileHandle);
			if (sha256cmp(sha256toverify, sha256digest)==0) {
				Print(L"File %s OK.\n", u16fn);
			} else {
				Print(L"File %s error.\n", u16fn);
				return EFI_ABORTED;
			}
		}
	}
	fileHandle->Close(fileHandle);
	return EFI_SUCCESS;
}

EFI_STATUS
setkey_card(EFI_CCID_PROTOCOL *ccid)
{
	EFI_STATUS Status;
	static unsigned char fpr[60];
	EFI_FILE_PROTOCOL *pubFileHandle;
	EFI_TIME curTime;
	unsigned char buffer[1024];
	unsigned char pw[256];
	UINTN pwlen;
	UINTN recvlen;

	SAFECALLE(Status, GetSlotStatus(ccid));
	SAFECALLE(Status, IccPowerOn(ccid));
	SAFECALLE(Status, resetParam(ccid));
	SAFECALLE(Status, GetSlotStatus(ccid));

	SAFECALLE(Status, SelectPGP(ccid));
	recvlen = 1024;
	SAFECALLE(Status, RecvData(ccid, buffer, &recvlen));
	if (buffer[recvlen-2]==0x90 && buffer[recvlen-1]==0x00) {
		Print(L"Select OpenPGP success.\n");
	} else {
		return EFI_ABORTED;
	}
	SAFECALLE(Status, PGP_GetData(ccid, OPENPGP_AID));
	recvlen = 1024;
	SAFECALLE(Status, RecvData(ccid, buffer, &recvlen));
	if (buffer[recvlen-2]==0x90 && buffer[recvlen-1]==0x00) {
		Print(L"Get AID success, AID:\n");
		for (UINTN i=0; i<recvlen-2; i++) {
			Print(L"%02x ", buffer[i]);
		}
		Print(L"\n");
	} else {
		return EFI_ABORTED;
	}
	SAFECALLE(Status, PGP_GetFingerprints(ccid, fpr));
	if (!havekey(fpr)) {
		return EFI_ABORTED;
	}
	AsciiPrint("Fingerprint found:\n");
	for (UINTN i=0; i<20; i++) {
		AsciiPrint("%02x", fpr[i]);
	}
	AsciiPrint("\n");
	keyid = fpr+16;
	targetu16fn(pubkeyfile);

	pubkeybuflen = sizeof(pubkeydata);
	SAFECALLE(Status, Root->Open(Root, &pubFileHandle, pubkeyfile, EFI_FILE_MODE_READ, 0));
	SAFECALLE(Status, pubFileHandle->Read(pubFileHandle, &pubkeybuflen, pubkeydata));
	SAFECALLE(Status, pubFileHandle->Close(pubFileHandle));
	AsciiPrint("%d bytes read from public key file.\n", (int)pubkeybuflen);

	if (find_pubkey(pubkeydata, pubkeybuflen, &rsakey, fpr+12)!=0) {
		AsciiPrint("Cannot find the public key of the OpenPGP card.\n");
		return EFI_ABORTED;
	}

	gRT->GetTime(&curTime, NULL);
	SHA256((const unsigned char*)&curTime, sizeof(curTime), sha256digestinfo+19);
	AsciiPrint("Enter PIN:");
	GetString(pw, &pwlen);
	SAFECALLE(Status, PGP_VerifyPW1(ccid, pw, pwlen));
	AsciiPrint("To sign:");
	for (int i=0; i<32; i++) {
		AsciiPrint("%02x ", sha256digestinfo[19+i]);
	}
	AsciiPrint("\n");
	SAFECALLE(Status, PGP_Sign(ccid, sha256digestinfo, SHA256_DIGEST_INFO_LEN));

	do {
		readlen = 1024;
		SAFECALLE(Status, RecvData(ccid, sigmsgbuf, &readlen));
	} while (readlen==0);
	sigbuflen = readlen-2;
	if (sigmsgbuf[sigbuflen]==0x90 && sigmsgbuf[sigbuflen+1]==0x00) {
		AsciiPrint("Signature received.\n");
	} else if (sigmsgbuf[sigbuflen]==0x61){
		UINTN requestlen = sigmsgbuf[sigbuflen+1];
		UINTN nextlen = requestlen;
		while (nextlen!=0) {
			AsciiPrint("To receive %d bytes...", requestlen);
			SAFECALLE(Status, PGP_GetResponse(ccid, sigmsgbuf+sigbuflen, requestlen, &nextlen));
			sigbuflen += requestlen;
			requestlen = nextlen;
		}
	} else {
		AsciiPrint("Receive signature error!\n");
			return EFI_ABORTED;
	}
	AsciiPrint("Signature length = %d\n", sigbuflen);
	if (sigverify(sigmsgbuf, sigbuflen, HASH_SHA256, sha256digestinfo+19, &rsakey)==1) {
		AsciiPrint("verify signature success!\n");
		return EFI_SUCCESS;
	} else {
		AsciiPrint("verify failed.\n");
		return EFI_ABORTED;
	}
}

static VOID EFIAPI
readyToBootEvt(
	IN EFI_EVENT Event,
	IN VOID *Context
	)
{
	EFI_STATUS Status;
	EFI_CCID_PROTOCOL *ccid;
	UINTN nHandles=0;
	EFI_HANDLE *controllerHandles = NULL;

	AsciiPrint("Now in readyToBootEvt notify function!\n");
	Status = GetFileIo(&Root);
	if (EFI_ERROR(Status)) {
		AsciiPrint("Cannot open EFI system partition!\n");
		return;
	}

	Status = gBS->LocateHandleBuffer(
		ByProtocol,
		&gEfiCcidProtocolGuid,
		NULL,
		&nHandles,
		&controllerHandles
		);
	if (EFI_ERROR(Status) || nHandles==0) {
		Print(L"Fail to locate CCID protocol.\n");
		setkey_nocard();
	} else {
		Status = gBS->HandleProtocol(
			controllerHandles[0],
			&gEfiCcidProtocolGuid,
			(VOID**)&ccid
			);
		if (EFI_ERROR(Status)) {
			Print(L"handle protocol failure, %d\n", Status);
			setkey_nocard();
		} else {
			if (EFI_ERROR(setkey_card(ccid))) {
				setkey_nocard();
			}
		}
	}

	if (keyid!=NULL) {
		AsciiPrint("Using keyid:\n");
		for (int i=0; i<4; i++) {
			AsciiPrint("%02x", keyid[i]);
		}
	}
	AsciiPrint("\n");

	if (verify_signed_hashlist()==EFI_SUCCESS) {
		AsciiPrint("verify signed hashlist success!\n");
	} else {
		AsciiPrint("verify error!\n");
		while (1);
	}

	if (verify_hashes()==EFI_SUCCESS) {
		AsciiPrint("verify hashes success!\n");
	} else {
		AsciiPrint("verify hashes failed!\n");
		while (1);
	}
}

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable
	)
{
	/* we just create an event in ReadyToBoot group,
		run the main function in notify funciton
	*/
	EFI_STATUS Status;

	SAFECALLE(Status, gBS->CreateEventEx(
					 EVT_NOTIFY_SIGNAL,
					 TPL_CALLBACK,
					 readyToBootEvt,
					 NULL,
					 &gEfiEventReadyToBootGuid,
					 &readytoboot
					 ));
	return EFI_SUCCESS;
}
