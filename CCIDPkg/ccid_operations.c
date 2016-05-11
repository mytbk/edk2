#include "ccid_proto.h"

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
	}

	return EFI_SUCCESS;
}
