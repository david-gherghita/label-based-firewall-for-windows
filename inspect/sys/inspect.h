#ifndef _TL_INSPECT_H_
#define _TL_INSPECT_H_

//
// TL_INSPECT_PENDED_PACKET is the object type we used to store all information
// needed for out-of-band packet modification and re-injection. This type
// also points back to the flow context the packet belongs to.

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION

#pragma warning(pop)

//
// Pooltags used by this callout driver.
//

#define NET_BUFFER_LIST_TAG 'ipcT'

//
// Shared global data.
//

extern BOOLEAN configPermitTraffic;

extern HANDLE injectionHandle;

extern NDIS_HANDLE netBufferListHandle;

extern LIST_ENTRY gConnList;
extern KSPIN_LOCK gConnListLock;

extern LIST_ENTRY gPacketQueue;
extern KSPIN_LOCK gPacketQueueLock;

extern KEVENT gWorkerEvent;

extern BOOLEAN gDriverUnloading;

//
// Shared function prototypes
//

void
TLInspectIPPacketClassify(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut
);

NTSTATUS
TLInspectIPPacketNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    const FWPS_FILTER* filter
);

#endif // _TL_INSPECT_H_
