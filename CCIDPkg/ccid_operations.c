#include "ccid_proto.h"
#include "tlv.h"
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

EFI_STATUS
GetSlotStatus(EFI_CCID_PROTOCOL *ccid)
{
	EFI_STATUS Status;
	UINT8 buffer[100];
	struct CCID_Header *pkt = (struct CCID_Header*)buffer;
	UINTN len=100;

	Status = ccid->Send(
		ccid,
		PC2RDR_GetSlotStatus,
		0,
		NULL, 0);
	if (EFI_ERROR(Status)) {
		Print(L"GetSlotStatus: CCID Send failure!\n");
		return Status;
	}

	Status = ccid->Recv(
		ccid,
		buffer,
		&len
		);
	if (EFI_ERROR(Status)) {
		Print(L"GetSlotStatus: CCID Recv failure!\n");
		return Status;
	}
	if (pkt->msgtype==RDR2PC_SlotStatus) {
		Print(L"Successfully get slot status.\n");
	} else {
		Print(L"Received a non SlotStatus message!\n");
	}

	Print(L"Slot Status: Status=%d Error=%d ClockStatus=%d\n",
			pkt->msgbyte[0], pkt->msgbyte[1], pkt->msgbyte[2]);
	return EFI_SUCCESS;
}

EFI_STATUS IccPowerOn(EFI_CCID_PROTOCOL *ccid)
{
	EFI_STATUS Status;
	UINT8 buffer[100];
	struct CCID_Header *pkt = (struct CCID_Header*)buffer;
	UINTN len=100;

	Status = ccid->Send(
		ccid,
		PC2RDR_IccPowerOn,
		0,
		NULL, 0);
	if (EFI_ERROR(Status)) {
		Print(L"IccPowerOn: CCID Send failure!\n");
		return Status;
	}

	Status = ccid->Recv(
		ccid,
		buffer,
		&len
		);
	if (EFI_ERROR(Status)) {
		Print(L"IccPowerOn: CCID Recv failure!\n");
		return Status;
	}
	if (pkt->msgtype==RDR2PC_DataBlock) {
		Print(L"IccPowerOn: Successfully get data block.\n");
	} else {
		Print(L"IccPowerOn: Received a non DataBlock message!\n");
	}

	Print(L"ATR data:\n");
	for (UINT32 i=0; i<pkt->length; i++) {
		Print(L"%02x ", pkt->payload[i]);
	}
	Print(L"\n");

	return EFI_SUCCESS;
}

/* first get parameters, then set the parameters as the same value,
	it's the sequence for initializing Yubikey 4
*/
EFI_STATUS resetParam(EFI_CCID_PROTOCOL *ccid)
{
	EFI_STATUS Status;
	UINT8 buffer[100];
	struct CCID_Header *pkt = (struct CCID_Header*)buffer;
	UINTN len=100;

	Status = ccid->Send(
		ccid,
		PC2RDR_GetParam,
		0,
		NULL, 0);
	if (EFI_ERROR(Status)) {
		Print(L"resetParam: CCID GetParam Send failure!\n");
		return Status;
	}

	Status = ccid->Recv(
		ccid,
		buffer,
		&len
		);
	if (EFI_ERROR(Status)) {
		Print(L"resetParam: CCID Recv failure!\n");
		return Status;
	}
	if (pkt->msgtype==RDR2PC_Param) {
		Print(L"resetParam: Successfully get parameters.\n");
	} else {
		Print(L"resetParam: Received a non parameter message!\n");
	}

	Status = ccid->Send(
		ccid,
		PC2RDR_SetParam,
		0,
		pkt->payload, pkt->length);
	if (EFI_ERROR(Status)) {
		Print(L"resetParam: CCID SetParam Send failure!\n");
		return Status;
	}

	len = sizeof(buffer);
	Status = ccid->Recv(
		ccid,
		buffer,
		&len
		);
	if (EFI_ERROR(Status)) {
		Print(L"resetParam: CCID Recv failure!\n");
		return Status;
	}
	if (pkt->msgtype==RDR2PC_SlotStatus) {
		Print(L"Slot Status received: Status=%d Error=%d ClockStatus=%d\n",
				pkt->msgbyte[0], pkt->msgbyte[1], pkt->msgbyte[2]);
	}

	return EFI_SUCCESS;
}

EFI_STATUS TransferBlock(
	EFI_CCID_PROTOCOL *ccid,
	const unsigned char *block,
	UINTN len)
{
	EFI_STATUS Status;

	Status = ccid->Send(
		ccid,
		PC2RDR_XfrBlock,
		0x04, /* block wait time integer: 4 */
		block, len);
	if (EFI_ERROR(Status)) {
		Print(L"TransferBlock: CCID Send failure!\n");
		return Status;
	} else {
		return EFI_SUCCESS;
	}
}

EFI_STATUS SelectPGP(EFI_CCID_PROTOCOL *ccid)
{
	const unsigned char *selectcmd = (const unsigned char*)
		"\x00\xa4\x04\x00\x06"
		"\xd2\x76\x00\x01\x24\x01";

	return TransferBlock(ccid, selectcmd, 11);
}

EFI_STATUS PGP_GetData(EFI_CCID_PROTOCOL *ccid, int addr)
{
	unsigned char getDataCmd[] = {0x00, 0xca, 0x00, 0x00, 0x00};
	getDataCmd[2] = (addr>>8)&0xff;
	getDataCmd[3] = addr&0xff;

	return TransferBlock(ccid, getDataCmd, 5);
}

EFI_STATUS RecvData(
	EFI_CCID_PROTOCOL *ccid,
	unsigned char *recvbuf,
	UINTN *len
	)
{
	UINTN recvlen = (*len)+10;
	EFI_STATUS Status;
	unsigned char *ccidbuf = AllocatePool(recvlen);
	struct CCID_Header *pkt = (struct CCID_Header*)ccidbuf;

	if (ccidbuf==NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	Status = ccid->Recv(
		ccid,
		ccidbuf,
		&recvlen
		);
	if (EFI_ERROR(Status)) {
		Print(L"RecvData: CCID Recv failure!\n");
		goto Error;
	}
	if (pkt->msgtype!=RDR2PC_DataBlock) {
		Print(L"RecvData: non-datablock received!\n");
		Status = EFI_ABORTED;
		goto Error;
	}
	CopyMem(recvbuf, pkt->payload, recvlen-10);
	*len = recvlen-10;
	Status = EFI_SUCCESS;

Error:
	if (ccidbuf) {
		FreePool(ccidbuf);
	}
	return Status;
}


EFI_STATUS
PGP_GetFingerprints(EFI_CCID_PROTOCOL* ccid, unsigned char sigs[])
{
	EFI_STATUS Status;
	unsigned char recvbuf[1024];
	UINTN recvlen = 1024;
	size_t n;

	SAFECALLE(Status, PGP_GetData(ccid, OPENPGP_APPLICATION_RELATED_DATA));
	SAFECALLE(Status, RecvData(ccid, recvbuf, &recvlen));

	if (recvbuf[recvlen-2]==0x90 && recvbuf[recvlen-1]==0x00) {
		const unsigned char *fpr = find_tlv(recvbuf, recvlen-2,
														OPENPGP_FINGERPRINTS, &n);
		if (!fpr || n<60) {
			Print(L"Error reading fingerprints!\n");
			return EFI_ABORTED;
		}

		CopyMem(sigs, fpr, 60);
		return EFI_SUCCESS;
	} else {
		Print(L"Get application related data failed, err=%02x%02x\n",
				recvbuf[recvlen-2], recvbuf[recvlen-1]);
		return EFI_ABORTED;
	}
}

/* verify PIN:
	return EFI_SUCCESS if PIN is correct,
	return EFI_ABORTED if PIN is wrong,
	otherwise there's some call error
*/
EFI_STATUS PGP_VerifyPW1(
	EFI_CCID_PROTOCOL *ccid,
	const unsigned char *pw,
	UINTN pwlen)
{
	EFI_STATUS Status;
	unsigned char recvbuf[1024];
	UINTN recvlen = 1024;

	unsigned char verifycmd[512] = {0x00, 0x20, 0x00, 0x81};
	verifycmd[4] = pwlen;
	CopyMem(verifycmd+5, pw, pwlen);

	SAFECALLE(Status, TransferBlock(ccid, verifycmd, 5+pwlen));
	SAFECALLE(Status, RecvData(ccid, recvbuf, &recvlen));

	if (recvbuf[recvlen-2]==0x90 && recvbuf[recvlen-1]==0x00) {
		return EFI_SUCCESS;
	} else {
		return EFI_ABORTED;
	}
}

EFI_STATUS PGP_Sign(
	EFI_CCID_PROTOCOL *ccid,
	const unsigned char *digestinfo,
	UINTN len_digestinfo)
{
	unsigned char signcmd[256] = {0x00, 0x2a, 0x9e, 0x9a};
	signcmd[4] = len_digestinfo;
	CopyMem(signcmd+5, digestinfo, len_digestinfo);
	signcmd[5+len_digestinfo] = 0x00;
	return TransferBlock(ccid, signcmd, 6+len_digestinfo);
}

EFI_STATUS PGP_GetResponse(
	EFI_CCID_PROTOCOL *ccid,
	unsigned char *buf,
	UINTN len,
	UINTN *nextlen
	)
{
	EFI_STATUS Status;
	unsigned char recvbuf[1024];
	UINTN recvlen=1024;

	unsigned char cmd[] = {0x00, 0xc0, 0x00, 0x00, 0x00};
	cmd[4] = len;
	SAFECALLE(Status, TransferBlock(ccid, cmd, 5));
	SAFECALLE(Status, RecvData(ccid, recvbuf, &recvlen));

	if (recvbuf[recvlen-2]==0x90 && recvbuf[recvlen-1]==0x00) {
		*nextlen = 0;
	} else if (recvbuf[recvlen-2]==0x61) {
		*nextlen = recvbuf[recvlen-1];
	}
	recvlen -= 2;
	if (recvlen!=len) {
		AsciiPrint("Response data doesn't have the same length as the request length!\n");
		return EFI_ABORTED;
	}
	CopyMem(buf, recvbuf, recvlen);
	return EFI_SUCCESS;
}
