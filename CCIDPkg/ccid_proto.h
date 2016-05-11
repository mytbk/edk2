#pragma once

#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/PlatformDriverOverride.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define EFI_CCID_PROTOCOL_GUID \
{ \
	 0x21b13e79, 0xfa25, 0x43e0, {0x93, 0xb4, 0x81, 0x05, 0x83, 0xdf, 0xbb, 0x65} \
}

///// Protocol GUID name defined in EFI1.1.
#define CCID_PROTOCOL  EFI_CCID_PROTOCOL_GUID
typedef struct _EFI_CCID_PROTOCOL EFI_CCID_PROTOCOL;

enum msgType {
	PC2RDR_IccPowerOn = 0x62,
	PC2RDR_IccPowerOff = 0x63,
	PC2RDR_GetSlotStatus = 0x65,
	PC2RDR_XfrBlock = 0x6f,
	PC2RDR_GetParam = 0x6c,
	PC2RDR_ResetParam = 0x6d,
	PC2RDR_SetParam = 0x61,
	PC2RDR_Escape = 0x6b,
	PC2RDR_IccClock = 0x6e,
	PC2RDR_T0APDU = 0x6a,
	PC2RDR_Secure = 0x69,
	PC2RDR_Mechanical = 0x71,
	PC2RDR_Abort = 0x72,
	PC2RDR_SetDataRate = 0x73,
	RDR2PC_DataBlock = 0x80,
	RDR2PC_SlotStatus = 0x81,
	RDR2PC_Param = 0x82,
	RDR2PC_Escape = 0x83,
	RDR2PC_DataRate = 0x84
};

/* 10-byte CCID message header,
	see CCID specification chapter 6
*/
struct CCID_Header
{
	unsigned char msgtype;
	UINT32 length;
	unsigned char slot;
	unsigned char seqNo;
	unsigned char msgbyte[3];
	unsigned char payload[0];
}__attribute__((packed));

typedef EFI_STATUS (EFIAPI *EFI_CCID_SEND_COMMAND)(
	EFI_CCID_PROTOCOL *This,
	unsigned char type,
	unsigned int msgtype,
	const char *payload,
	UINTN len
	);
typedef EFI_STATUS (EFIAPI *EFI_CCID_RECV_RESPONSE)(
	EFI_CCID_PROTOCOL *This,
	unsigned char *buffer,
	UINTN *len
	);

struct _EFI_CCID_PROTOCOL
{
	UINTN Revision;
	EFI_CCID_SEND_COMMAND Send;
	EFI_CCID_RECV_RESPONSE Recv;
};

extern EFI_GUID gEfiAudioProtocolGUID;
