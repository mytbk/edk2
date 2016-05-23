#include <Uefi.h>
#include <Base.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Protocol/UsbIo.h>
#include <Protocol/DriverBinding.h>

#include "ccid_proto.h"

extern EFI_COMPONENT_NAME_PROTOCOL gCcidComponentName;
extern EFI_COMPONENT_NAME2_PROTOCOL gCcidComponentName2;
EFI_GUID gEfiCcidProtocolGuid = EFI_CCID_PROTOCOL_GUID;

static EFI_STATUS EFIAPI
CCIDDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  );

static EFI_STATUS EFIAPI
CCIDDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  );

static EFI_STATUS EFIAPI
CCIDDriverBindingStop (
  IN  EFI_DRIVER_BINDING_PROTOCOL    *This,
  IN  EFI_HANDLE                     ControllerHandle,
  IN  UINTN                          NumberOfChildren,
  IN  EFI_HANDLE                     *ChildHandleBuffer
  );

static EFI_STATUS EFIAPI CCIDSend(
	EFI_CCID_PROTOCOL *This,
	unsigned char type,
	unsigned int msgbyte,
	const unsigned char* payload,
	UINTN len);
static EFI_STATUS EFIAPI CCIDRecv(
	EFI_CCID_PROTOCOL *,
	unsigned char *,
	UINTN *
	);

#define CCID_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('C', 'C', 'I', 'D')
#define EFI_CCID_PROTOCOL_REVISION  0x1

typedef struct {
	UINTN Signature;
	EFI_CCID_PROTOCOL ccid_proto;
	EFI_USB_IO_PROTOCOL *usbio;
	UINT8 inEndpoint;
	UINT8 outEndpoint;
	unsigned char seqNo;
} CCID_PRIVATE_DATA;

#define CCID_PRIVATE_DATA_FROM_THIS(a) CR (a, CCID_PRIVATE_DATA, ccid_proto, CCID_PRIVATE_DATA_SIGNATURE)
//static AUDIO_PRIVATE_DATA gAudioPrivate;

//
// Driver binding protocol implementation for AC97 driver.
//
EFI_DRIVER_BINDING_PROTOCOL gCcidDriverBinding = {
  CCIDDriverBindingSupported,
  CCIDDriverBindingStart,
  CCIDDriverBindingStop,
  0xa,
  NULL,
  NULL
};

/*
  Template for CCID private data structure.
  The pointer to CCID protocol interface is assigned dynamically.
*/
CCID_PRIVATE_DATA gCCIDPrivateDataTemplate = {
	CCID_PRIVATE_DATA_SIGNATURE,
	{
		EFI_CCID_PROTOCOL_REVISION,
		CCIDSend,
		CCIDRecv,
	},
	NULL,
	0x82,
	0x02,
	0
};

/**
  Test to see if this driver supports ControllerHandle.

  @param  This                Protocol instance pointer.
  @param  ControllerHandle    Handle of device to test
  @param  RemainingDevicePath Optional parameter use to pick a specific child
                              device to start.

  @retval EFI_SUCCESS         This driver supports this device
  @retval EFI_ALREADY_STARTED This driver is already running on this device
  @retval other               This driver does not support this device

**/

static EFI_STATUS EFIAPI
CCIDDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  )
{
	EFI_STATUS Status;
	EFI_USB_IO_PROTOCOL *usbio;
	EFI_USB_INTERFACE_DESCRIPTOR interface;

	Status = gBS->HandleProtocol(
		ControllerHandle,
		&gEfiUsbIoProtocolGuid,
		(VOID**)&usbio
		);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	Status = usbio->UsbGetInterfaceDescriptor(usbio, &interface);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	gBS->CloseProtocol(ControllerHandle, &gEfiUsbIoProtocolGuid,
							 This->DriverBindingHandle, ControllerHandle);
	if (interface.InterfaceClass!=11) {
		/* not a CCID device */
		return EFI_UNSUPPORTED;
	}
	return EFI_SUCCESS;
}

/**
  Start this driver on ControllerHandle by opening a PCI IO protocol and
  installing a Audio IO protocol on ControllerHandle.

  @param  This                 Protocol instance pointer.
  @param  ControllerHandle     Handle of device to bind driver to
  @param  RemainingDevicePath  Optional parameter use to pick a specific child
                               device to start.

  @retval EFI_SUCCESS          This driver is added to ControllerHandle
  @retval EFI_ALREADY_STARTED  This driver is already running on ControllerHandle
  @retval other                This driver does not support this device

**/
static EFI_STATUS EFIAPI
CCIDDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  )
{
	EFI_STATUS Status;
	EFI_USB_IO_PROTOCOL *usbio;
	CCID_PRIVATE_DATA *Private;
	EFI_USB_INTERFACE_DESCRIPTOR interface;
	EFI_USB_ENDPOINT_DESCRIPTOR endpoint;
	UINTN Index;
	
	Print(L"CCID driver bound to a controller handle.\n");

	Status = gBS->OpenProtocol(
		ControllerHandle,
		&gEfiUsbIoProtocolGuid,
		(VOID**)&usbio,
		This->DriverBindingHandle,
		ControllerHandle,
		EFI_OPEN_PROTOCOL_BY_DRIVER
		);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	Private = AllocateCopyPool(
		sizeof(CCID_PRIVATE_DATA),
		&gCCIDPrivateDataTemplate);
	if (Private==NULL) {
		return EFI_OUT_OF_RESOURCES;
	}
	Private->usbio = usbio;

	SAFECALLE(Status, usbio->UsbGetInterfaceDescriptor(usbio, &interface));
	for (Index=0; Index<interface.NumEndpoints; Index++) {
		Status = usbio->UsbGetEndpointDescriptor(usbio, Index, &endpoint);
		if (!EFI_ERROR(Status)) {
			if ((endpoint.Attributes & 0x3)==2) { /* Bulk endpoint */
				if ((endpoint.EndpointAddress&0x80)) {
					/* in endpoint */
					Private->inEndpoint = endpoint.EndpointAddress;
				} else {
					Private->outEndpoint = endpoint.EndpointAddress;
				}
			}
		}
	}
	Status = gBS->InstallProtocolInterface(
		&ControllerHandle,
		&gEfiCcidProtocolGuid,
		EFI_NATIVE_INTERFACE,
		&Private->ccid_proto
		);
	if (EFI_ERROR(Status)) {
		if (Private!=NULL) {
			FreePool(Private);
		}
		gBS->CloseProtocol(
			ControllerHandle,
			&gEfiUsbIoProtocolGuid,
			This->DriverBindingHandle,
			ControllerHandle
			);
	}
   return EFI_SUCCESS;

}

/**
  Stop this driver on ControllerHandle by removing Audio IO protocol and closing
  the PCI IO protocol on ControllerHandle.

  @param  This              Protocol instance pointer.
  @param  ControllerHandle  Handle of device to stop driver on
  @param  NumberOfChildren  Number of Handles in ChildHandleBuffer. If number of
                            children is zero stop the entire bus driver.
  @param  ChildHandleBuffer List of Child Handles to Stop.

  @retval EFI_SUCCESS       This driver is removed ControllerHandle
  @retval other             This driver was not removed from this device

**/

static EFI_STATUS EFIAPI
CCIDDriverBindingStop (
  IN  EFI_DRIVER_BINDING_PROTOCOL    *This,
  IN  EFI_HANDLE                     ControllerHandle,
  IN  UINTN                          NumberOfChildren,
  IN  EFI_HANDLE                     *ChildHandleBuffer
  )
{
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
CCIDSend(EFI_CCID_PROTOCOL *This,
			unsigned char type,
			unsigned int msgbyte,
			const unsigned char* payload, UINTN len)
{
	CCID_PRIVATE_DATA *priv = CCID_PRIVATE_DATA_FROM_THIS(This);
	struct CCID_Header *pkt = AllocatePool(len+10);
	EFI_STATUS Status;
	UINT32 err;
	UINTN xferlen = len+10;

	pkt->msgtype = type;
	pkt->length = len;
	pkt->slot = 0; /* FIXME: now only slot 0 is supported */
	pkt->seqNo = priv->seqNo;
	pkt->msgbyte[0] = msgbyte;
	pkt->msgbyte[1] = msgbyte>>8;
	pkt->msgbyte[2] = msgbyte>>16;
	if (len!=0) {
		CopyMem(pkt->payload, payload, len);
	}
	priv->seqNo++;
	Status = priv->usbio->UsbBulkTransfer(
		priv->usbio,
		priv->outEndpoint,
		pkt,
		&xferlen,
		0,
		&err);
	if (EFI_ERROR(Status)) {
		Print(L"Error %d in CCIDSend!\n", err);
	}
	FreePool(pkt);

	return Status;
}

static EFI_STATUS EFIAPI
CCIDRecv(EFI_CCID_PROTOCOL *This,
			unsigned char* buffer, UINTN *len)
{
	EFI_STATUS Status;
	UINT32 err;
	CCID_PRIVATE_DATA *priv = CCID_PRIVATE_DATA_FROM_THIS(This);

	Status = priv->usbio->UsbBulkTransfer(
		priv->usbio,
		priv->inEndpoint,
		buffer,
		len,
		0,
		&err
		);
	if (EFI_ERROR(Status)) {
		Print(L"Error in CCIDRecv, Status=%d, err=%d!\n", Status, err);
	}
	return Status;
}

EFI_STATUS
EFIAPI
InitializeCCID(
	IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE  *SystemTable
	)
{
    EFI_STATUS Status;
    //
    // Install driver model protocol(s).
    //
    Status = EfiLibInstallDriverBindingComponentName2 (
		 ImageHandle,
		 SystemTable,
		 &gCcidDriverBinding,
		 ImageHandle,
		 &gCcidComponentName,
		 &gCcidComponentName2
		 );
    //ASSERT_EFI_ERROR (Status);
    return Status;
}
