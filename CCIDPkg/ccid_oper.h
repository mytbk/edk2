#pragma once

#include "ccid_proto.h"

EFI_STATUS GetSlotStatus(EFI_CCID_PROTOCOL *ccid);
EFI_STATUS IccPowerOn(EFI_CCID_PROTOCOL *ccid);
/* first get parameters, then set the parameters as the same value,
	it's the sequence for initializing Yubikey 4
*/
EFI_STATUS resetParam(EFI_CCID_PROTOCOL *ccid);
EFI_STATUS TransferBlock(
	EFI_CCID_PROTOCOL *ccid,
	const unsigned char *block,
	UINTN len);
EFI_STATUS SelectPGP(EFI_CCID_PROTOCOL *ccid);
EFI_STATUS PGP_GetData(EFI_CCID_PROTOCOL *ccid, int addr);
EFI_STATUS RecvData(
	EFI_CCID_PROTOCOL *ccid,
	unsigned char *recvbuf,
	UINTN *len
	);
EFI_STATUS PGP_GetFingerprints(EFI_CCID_PROTOCOL* ccid, unsigned char sigs[]);
/* verify PIN:
	return EFI_SUCCESS if PIN is correct,
	return EFI_ABORTED if PIN is wrong,
	otherwise there's some call error
*/
EFI_STATUS PGP_VerifyPW1(
	EFI_CCID_PROTOCOL *ccid,
	const unsigned char *pw,
	UINTN pwlen);
EFI_STATUS PGP_Sign(
	EFI_CCID_PROTOCOL *ccid,
	const unsigned char *digestinfo,
	UINTN len_digestinfo);
