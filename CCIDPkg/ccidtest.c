#include "ccid_oper.h"
#include <openpgp/cryptodata.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/UsbIo.h>
#include <Library/UefiUsbLib.h>
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

const char *charmap = "0123456789abcdef";
static unsigned char *keyid = NULL;
static CHAR16* pubkeyfile = L"xxxxxxxx.gpg";
static unsigned char pubkeydata[8192];
static UINTN pubkeybuflen;
static struct RSA_pubkey rsakey;
static unsigned char sigmsgbuf[1024];
static unsigned int sigbuflen=0;
static UINTN readlen=0;

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

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable
	)
{
	EFI_CCID_PROTOCOL *ccid;
	EFI_STATUS Status;
	UINTN nHandles;
	EFI_HANDLE *controllerHandles = NULL;
	unsigned char buffer[1024];
	unsigned char sigs[60];
	unsigned char pw[256];
	UINTN pwlen;
	UINTN recvlen;

	Status = gBS->LocateHandleBuffer(
		ByProtocol,
		&gEfiCcidProtocolGuid,
		NULL,
		&nHandles,
		&controllerHandles
		);
	if (EFI_ERROR(Status)) {
		Print(L"Fail to locate CCID protocol.\n");
		return Status;
	}
	Print(L"%d handles found.\n", nHandles);

	for (INTN handleIndex=0; handleIndex<nHandles; handleIndex++) {
		Status = gBS->HandleProtocol(
			controllerHandles[handleIndex],
			&gEfiCcidProtocolGuid,
			(VOID**)&ccid
			);
		if (EFI_ERROR(Status)) {
			Print(L"handle protocol failure, %d\n", Status);
			return Status;
		}

		EFI_USB_IO_PROTOCOL *ccidusb;
		Status = gBS->HandleProtocol(
			controllerHandles[handleIndex],
			&gEfiUsbIoProtocolGuid,
			(VOID**)&ccidusb
			);
		if (EFI_ERROR(Status)) {
			AsciiErrorPrint("failed to find usb protocol, status=%d\n", Status);
			return Status;
		}
		EFI_USB_CONFIG_DESCRIPTOR usbdesc;
		ccidusb->UsbGetConfigDescriptor(
			ccidusb,
			&usbdesc
			);
		AsciiPrint("numInterfaces=%d bConfigVal=%d iConfig=%d\n",
					  usbdesc.NumInterfaces,
					  usbdesc.ConfigurationValue,
					  usbdesc.Configuration
			);
		Status = ccidusb->UsbPortReset(ccidusb);
		if (EFI_ERROR(Status)) {
			AsciiErrorPrint("error resetting!\n");
			return Status;
		}
		UINT16 Config;
		UINT32 err;
		Status = UsbGetConfiguration(
			ccidusb,
			&Config,
			&err
			);
		if (EFI_ERROR(Status)) {
			AsciiErrorPrint("get configuration error: Status=%d, err=%d\n", Status, err);
			return Status;
		}
		AsciiPrint("Configuration=%d\n", Config);
		Status = UsbSetConfiguration(
			ccidusb,
			1,
			&err
			);
		if (EFI_ERROR(Status)) {
			AsciiErrorPrint("set configuration failure: Status=%d, err=%d\n", Status, err);
			return Status;
		}

		Status = GetSlotStatus(ccid);
		if (EFI_ERROR(Status)) {
			AsciiErrorPrint("Fail to get slot status.\n");
			return Status;
		}
		Status = IccPowerOn(ccid);
		if (EFI_ERROR(Status)) {
			Print(L"Fail to power on the card.\n");
			return Status;
		}
		Status = resetParam(ccid);
		if (EFI_ERROR(Status)) {
			Print(L"Fail to reset parameters.\n");
			return Status;
		}
		Status = GetSlotStatus(ccid);
		if (EFI_ERROR(Status)) {
			Print(L"Fail to get slot status.\n");
			return Status;
		}

		SAFECALLE(Status, SelectPGP(ccid));
		recvlen = 1024;
		SAFECALLE(Status, RecvData(ccid, buffer, &recvlen));
		if (buffer[recvlen-2]==0x90 && buffer[recvlen-1]==0x00) {
			Print(L"Select OpenPGP success.\n");
		}

		SAFECALLE(Status, PGP_GetData(ccid, OPENPGP_AID));

		recvlen = 1024;
		SAFECALLE(Status, RecvData(ccid, buffer, &recvlen));
		if (buffer[recvlen-2]==0x90 && buffer[recvlen-1]==0x00) {
			Print(L"Get AID success, AID:\n");
		}
		for (UINTN i=0; i<recvlen-2; i++) {
			Print(L"%02x ", buffer[i]);
		}
		Print(L"\n");

		SAFECALLE(Status, PGP_GetData(ccid, OPENPGP_URL));

		recvlen = 1024;
		SAFECALLE(Status, RecvData(ccid, buffer, &recvlen));
		if (buffer[recvlen-2]==0x90 && buffer[recvlen-1]==0x00) {
			Print(L"URL: ");
		}
		for (UINTN i=0; i<recvlen-2; i++) {
			Print(L"%c", buffer[i]);
		}
		Print(L"\n");

		SAFECALLE(Status, PGP_GetFingerprints(ccid, sigs));
		for (UINTN i=0; i<20; i++) {
			Print(L"%02x", sigs[i]);
		}
		Print(L"\n");
		keyid = sigs+16;
		targetu16fn(pubkeyfile);
		Print(pubkeyfile);
		Print(L"\n");

		EFI_FILE_PROTOCOL *Root;
		EFI_FILE_PROTOCOL *pubFileHandle;
		pubkeybuflen = sizeof(pubkeydata);
		SAFECALLE(Status, GetFileIo(&Root));
		SAFECALLE(Status, Root->Open(Root, &pubFileHandle, pubkeyfile, EFI_FILE_MODE_READ, 0));
		SAFECALLE(Status, pubFileHandle->Read(pubFileHandle, &pubkeybuflen, pubkeydata));
		SAFECALLE(Status, pubFileHandle->Close(pubFileHandle));
		AsciiPrint("%d bytes read from public key file.\n", (int)pubkeybuflen);

		if (find_pubkey(pubkeydata, pubkeybuflen, &rsakey, sigs+12)!=0) {
			AsciiPrint("Cannot find the public key of the OpenPGP card.\n");
			return EFI_ABORTED;
		}

		EFI_TIME curTime;
		gRT->GetTime(&curTime, NULL);
		SHA256((const unsigned char*)&curTime, sizeof(curTime), sha256digestinfo+19);
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
		} else {
			AsciiPrint("verify failed.\n");
		}
	}

	return EFI_SUCCESS;
}
