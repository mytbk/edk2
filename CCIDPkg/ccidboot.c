#include "ccid_oper.h"
#include <openpgp/cryptodata.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimpleTextInEx.h>
#include <Guid/FileInfo.h>
#include <openssl/sha.h>

#define TESTPATTERN0 "abcd1234" \
	"abcd1234" \
	"deadbeef" \
	"deadbeef"

#define TESTPATTERN1 "\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x00\x00\x00\x00\x00\x00\x00\x00"

static unsigned char *sha256digestinfo = (unsigned char*)
	"\x30\x31"
	"\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"
	"\x04\x20"
	TESTPATTERN0;

#define SHA256_DIGEST_INFO_LEN 51

static const char *charmap = "0123456789abcdef";
static unsigned char *keyid = NULL;
static CHAR16* pubkeyfile = L"xxxxxxxx.gpg";
static CHAR16* hashlist = L"xxxxxxxx.sha256sums";
static CHAR16* hashlistsig = L"xxxxxxxx.sha256sums.sig";
static unsigned char pubkeydata[1<<20];
static UINTN pubkeybuflen;
static struct RSA_pubkey rsakey;
static unsigned char sigmsgbuf[1024];
static unsigned int sigbuflen=0;
static UINTN readlen=0;
EFI_FILE_PROTOCOL *Root;

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
	keyid = NULL;
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

int verify_hashes()
{
	return 0;
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

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable
	)
{
	EFI_CCID_PROTOCOL *ccid;
	EFI_STATUS Status;
	UINTN nHandles=0;
	EFI_HANDLE *controllerHandles = NULL;

	SAFECALLE(Status, GetFileIo(&Root));

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
	}

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
	}

	return EFI_SUCCESS;
}
