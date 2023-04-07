#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "inspect.h"

#define INITGUID
#include <guiddef.h>

// 
// Configurable parameters (addresses and ports are in host order)
//

BOOLEAN configPermitTraffic = TRUE;

UINT8*   configInspectRemoteAddrV4 = NULL;

IN_ADDR  remoteAddrStorageV4;

// 
// Callout and sublayer GUIDs
//

// 2e207682-d95f-4525-b966-969f26587f03
DEFINE_GUID(
    TL_INSPECT_SUBLAYER,
    0x2e207682,
    0xd95f,
    0x4525,
    0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

// A807C9EE-3848-4CC1-B90B-8D12AD96DBBA
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_IPPACKET_CALLOUT_V4,
    0xa807c9ee,
    0x3848,
    0x4cc1,
    0xb9, 0xb, 0x8d, 0x12, 0xad, 0x96, 0xdb, 0xba
);

// 
// Callout driver global variables
//

DEVICE_OBJECT* gWdmDevice;
WDFKEY gParametersKey;

HANDLE gEngineHandle;
UINT32 gOutboundIPCalloutIdV4;

HANDLE injectionHandle;

NDIS_HANDLE netBufferListHandle;

BOOLEAN gDriverUnloading = FALSE;

// 
// Callout driver implementation
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TLInspectEvtDriverUnload;

NTSTATUS
TLInspectLoadConfig(
   _In_ const WDFKEY key
   )
{
   NTSTATUS status;
   DECLARE_CONST_UNICODE_STRING(valueName, L"RemoteAddressToInspect");
   DECLARE_UNICODE_STRING_SIZE(value, INET6_ADDRSTRLEN);
   
   status = WdfRegistryQueryUnicodeString(key, &valueName, NULL, &value);

   if (NT_SUCCESS(status))
   {
      PWSTR terminator;
      // Defensively null-terminate the string
      value.Length = min(value.Length, value.MaximumLength - sizeof(WCHAR));
      value.Buffer[value.Length/sizeof(WCHAR)] = UNICODE_NULL;

      status = RtlIpv4StringToAddressW(
                  value.Buffer,
                  TRUE,
                  &terminator,
                  &remoteAddrStorageV4
                  );
      if (NT_SUCCESS(status))
      {
         remoteAddrStorageV4.S_un.S_addr = 
            RtlUlongByteSwap(remoteAddrStorageV4.S_un.S_addr);
         configInspectRemoteAddrV4 = &remoteAddrStorageV4.S_un.S_un_b.s_b1;
      }
   }

   return status;
}

NTSTATUS
TLInspectAddFilter(
   _In_ const wchar_t* filterName,
   _In_ const wchar_t* filterDesc,
   _In_reads_opt_(16) const UINT8* remoteAddr,
   _In_ UINT64 context,
   _In_ const GUID* layerKey,
   _In_ const GUID* calloutKey
   )
{
    (remoteAddr);

   NTSTATUS status = STATUS_SUCCESS;

   FWPM_FILTER filter = {0};
   FWPM_FILTER_CONDITION filterConditions[3] = {0}; 
   UINT conditionIndex;

   filter.layerKey = *layerKey;
   filter.displayData.name = (wchar_t*)filterName;
   filter.displayData.description = (wchar_t*)filterDesc;

   filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
   filter.action.calloutKey = *calloutKey;
   filter.filterCondition = filterConditions;
   filter.subLayerKey = TL_INSPECT_SUBLAYER;
   filter.weight.type = FWP_EMPTY; // auto-weight.
   filter.rawContext = context;

   conditionIndex = 0;

   /*if (remoteAddr != NULL)
   {
        filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;
        //-------------------------------------------
        // IPV4 ONLY
        //-------------------------------------------
        filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
        filterConditions[conditionIndex].conditionValue.uint32 = *(UINT32*)remoteAddr;

        conditionIndex++;
   }*/

   filter.numFilterConditions = conditionIndex;

   status = FwpmFilterAdd(
               gEngineHandle,
               &filter,
               NULL,
               NULL);

   return status;
}

NTSTATUS
TLInspectRegisterIPPacketCallouts(
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey,
    _Inout_ void* deviceObject,
    _Out_ UINT32* calloutId
)
{
    NTSTATUS status = STATUS_SUCCESS;

    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };

    FWPM_DISPLAY_DATA displayData = { 0 };

    BOOLEAN calloutRegistered = FALSE;

    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = TLInspectIPPacketClassify;
    sCallout.notifyFn = TLInspectIPPacketNotify;

    status = FwpsCalloutRegister(
        deviceObject,
        &sCallout,
        calloutId
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FIREWALL: Eroare la FwpsCalloutRegister");
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = L"IPPacket Inspect Callout";
    displayData.description = L"Inspect inbound/outbound IPPacket traffic";

    mCallout.calloutKey = *calloutKey;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = *layerKey;

    status = FwpmCalloutAdd(
        gEngineHandle,
        &mCallout,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("FIREWALL: Eroare la FwpmCalloutAdd");
        goto Exit;
    }

    status = TLInspectAddFilter(
        L"IPPacket Inspect Filter (Outbound)",
        L"Inspect inbound/outbound IPPacket traffic",
        configInspectRemoteAddrV4,
        0,
        layerKey,
        calloutKey
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("FIREWALL: Eroare la TLInspectAddFilter");
        goto Exit;
    }
 
Exit:

    if (!NT_SUCCESS(status))
    {
        if (calloutRegistered)
        {
            FwpsCalloutUnregisterById(*calloutId);
            *calloutId = 0;
        }
    }

    return status;
}

NTSTATUS
TLInspectRegisterCallouts(
   _Inout_ void* deviceObject
   )
/* ++

   This function registers dynamic callouts and filters that intercept 
   transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and 
   INBOUND/OUTBOUND transport layers.

   Callouts and filters will be removed during DriverUnload.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;
   FWPM_SUBLAYER TLInspectSubLayer;

   BOOLEAN engineOpened = FALSE;
   BOOLEAN inTransaction = FALSE;

   FWPM_SESSION session = {0};

   session.flags = FWPM_SESSION_FLAG_DYNAMIC;

   status = FwpmEngineOpen(
                NULL,
                RPC_C_AUTHN_WINNT,
                NULL,
                &session,
                &gEngineHandle
                );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   engineOpened = TRUE;

   status = FwpmTransactionBegin(gEngineHandle, 0);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = TRUE;

   RtlZeroMemory(&TLInspectSubLayer, sizeof(FWPM_SUBLAYER)); 

   TLInspectSubLayer.subLayerKey = TL_INSPECT_SUBLAYER;
   TLInspectSubLayer.displayData.name = L"Transport Inspect Sub-Layer";
   TLInspectSubLayer.displayData.description = 
      L"Sub-Layer for use by Transport Inspect callouts";
   TLInspectSubLayer.flags = 0;
   TLInspectSubLayer.weight = 0; // must be less than the weight of 
                                 // FWPM_SUBLAYER_UNIVERSAL to be
                                 // compatible with Vista's IpSec
                                 // implementation.

   status = FwpmSubLayerAdd(gEngineHandle, &TLInspectSubLayer, NULL);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   if (configInspectRemoteAddrV4 != NULL)
   {
      status = TLInspectRegisterIPPacketCallouts(
                &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
                &TL_INSPECT_OUTBOUND_IPPACKET_CALLOUT_V4,
                deviceObject,
                &gOutboundIPCalloutIdV4
                );
      if (!NT_SUCCESS(status))
      {
          goto Exit;
      }
   }

   status = FwpmTransactionCommit(gEngineHandle);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = FALSE;

Exit:

   if (!NT_SUCCESS(status))
   {
      if (inTransaction)
      {
         FwpmTransactionAbort(gEngineHandle);
         _Analysis_assume_lock_not_held_(gEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
      }
      if (engineOpened)
      {
         FwpmEngineClose(gEngineHandle);
         gEngineHandle = NULL;
      }
   }

   return status;
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
TLInspectEvtDriverUnload(
   _In_ WDFDRIVER driverObject
   )
{
   UNREFERENCED_PARAMETER(driverObject);

   gDriverUnloading = TRUE;

    if (gEngineHandle)
    {
        FwpmEngineClose(gEngineHandle);
        gEngineHandle = NULL;
    }

    if (gOutboundIPCalloutIdV4)
    {
        FwpsCalloutUnregisterById(gOutboundIPCalloutIdV4);
    }

    if (injectionHandle)
    { 
        FwpsInjectionHandleDestroy(injectionHandle);
    }
   
    if (netBufferListHandle)
    {
        NdisFreeNetBufferListPool(netBufferListHandle);
    }
}

NTSTATUS
TLInspectInitDriverObjects(
   _Inout_ DRIVER_OBJECT* driverObject,
   _In_ const UNICODE_STRING* registryPath,
   _Out_ WDFDRIVER* pDriver,
   _Out_ WDFDEVICE* pDevice
   )
{
   NTSTATUS status;
   WDF_DRIVER_CONFIG config;
   PWDFDEVICE_INIT pInit = NULL;

   WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

   config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
   config.EvtDriverUnload = TLInspectEvtDriverUnload;

   status = WdfDriverCreate(
               driverObject,
               registryPath,
               WDF_NO_OBJECT_ATTRIBUTES,
               &config,
               pDriver
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_KERNEL_ONLY);
   if (!pInit)
   {
      status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
   }

   WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
   WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
   WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

   status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);
   if (!NT_SUCCESS(status))
   {
      WdfDeviceInitFree(pInit);
      goto Exit;
   }

   WdfControlFinishInitializing(*pDevice);

Exit:
   return status;
}

NTSTATUS
DriverEntry(
   DRIVER_OBJECT* driverObject,
   UNICODE_STRING* registryPath
   )
{
   NTSTATUS status;
   WDFDRIVER driver;
   WDFDEVICE device;

   // Request NX Non-Paged Pool when available
   ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

   status = TLInspectInitDriverObjects(
               driverObject,
               registryPath,
               &driver,
               &device
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = WdfDriverOpenParametersRegistryKey(
               driver,
               KEY_READ,
               WDF_NO_OBJECT_ATTRIBUTES,
               &gParametersKey
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLInspectLoadConfig(gParametersKey);

   if (!NT_SUCCESS(status))
   {
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
      goto Exit;
   }

   if (configInspectRemoteAddrV4 == NULL)
   {
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
      goto Exit;
   }

   status = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &injectionHandle);
   if (!NT_SUCCESS(status))
   {
       DbgPrint("FIREWALL: FwpsInjectionHandleCreate failed with %x", status);
       goto Exit;
   }
   DbgPrint("FIREWALL: injectionHandle - %p", injectionHandle);

   gWdmDevice = WdfDeviceWdmGetDeviceObject(device);

   status = TLInspectRegisterCallouts(gWdmDevice);

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   NET_BUFFER_LIST_POOL_PARAMETERS netBufferListParameters = {
        .Header = {.Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
        .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
        .PoolTag = 'IpcT',
        .fAllocateNetBuffer = TRUE,
        .DataSize = 0
   };

   netBufferListHandle = NdisAllocateNetBufferListPool(NULL, &netBufferListParameters);
   if (!netBufferListHandle)
   {
       DbgPrint("FIREWALL: NdisAllocateNetBufferListPool failed");
       return STATUS_INSUFFICIENT_RESOURCES;
   }

Exit:
   
   if (!NT_SUCCESS(status))
   {
      if (gEngineHandle != NULL)
      {
         //TLInspectUnregisterCallouts();
      }
      if (injectionHandle != NULL) {
         FwpsInjectionHandleDestroy(injectionHandle);
      }
   }

   return status;
};

