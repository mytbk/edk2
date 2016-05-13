#include "ccid_proto.h"
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

#ifndef SAFECALLE
#define SAFECALLE(v,e) v=e; \
	if (EFI_ERROR(v)) {Print(L"%s failed.\n", #e); return v;}
#endif

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
		Status = GetSlotStatus(ccid);
		if (EFI_ERROR(Status)) {
			Print(L"Fail to get slot status.\n");
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
	}

	return EFI_SUCCESS;
}
