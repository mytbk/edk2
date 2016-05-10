/*
 * =====================================================================================
 *
 *       Filename:  audio.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  05/10/2012 08:07:46 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  DAI ZHENGHUA (), djx.zhenghua@gmail.com
 *        Company:  
 *
 * =====================================================================================
 */
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

typedef EFI_STATUS (EFIAPI *EFI_CCID_SEND_COMMAND)(
	EFI_CCID_PROTOCOL *This,
	const char *cmd,
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


