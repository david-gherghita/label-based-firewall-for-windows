#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include "inspect.h"

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

USHORT IpChecksum(void* buf, UINT size)
{
    int sum = 0;
    USHORT* addr = (USHORT*)buf;
    int len = (int)size;
    USHORT* w = addr;
    int nleft = len;
    USHORT answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(UCHAR*)(&answer) = *(UCHAR*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    answer = (USHORT)~sum;

    return answer;
}

typedef struct NetBufferListStorage
{
    NDIS_HANDLE             handle;
    PVOID                   oldBuffer;
    PVOID                   ptr;
    PMDL                    mdl;
    PNET_BUFFER_LIST        list;
} NetBufferListStorage;

static void FreeNetworkBufferListStorage(NetBufferListStorage* storage)
{
    if (!storage)
    {
        return;
    }

    if (storage->oldBuffer)
    {
        ExFreePoolWithTag(storage->oldBuffer, NET_BUFFER_LIST_TAG);
    }

    if (storage->ptr)
    {
        ExFreePoolWithTag(storage->ptr, NET_BUFFER_LIST_TAG);
    }

    if (storage->mdl)
    {
        IoFreeMdl(storage->mdl);
    }

    if (storage->list)
    {
        FwpsFreeNetBufferList(storage->list);
    }

    ExFreePoolWithTag(storage, NET_BUFFER_LIST_TAG);
}

void FwpsInjectComplete(
    _In_ void* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(netBufferList);
    UNREFERENCED_PARAMETER(dispatchLevel);

    FreeNetworkBufferListStorage((NetBufferListStorage*)context);
}

void
TLInspectIPPacketClassify(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut
)
{
    NTSTATUS status;

    (inFixedValues);
    (inMetaValues);
    (layerData);
    (classifyContext);
    (filter);
    (flowContext);
    (classifyOut);
    (status);
    
    DbgPrint("FIREWALL: TLInspectIPPacketClassify - START");

    if (layerData == NULL) {
        DbgPrint("FIREWALL: TLInspectIPPacketClassify - layerData is NULL");
        return;
    }

    // Get state of the packet
    FWPS_PACKET_INJECTION_STATE packetState = FwpsQueryPacketInjectionState(
        injectionHandle,
        layerData,
        NULL
    );

    // Permit or Block
    if ((packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
        (packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF))
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;

        DbgPrint("FIREWALL: Exiting - Packet was injected");
        return;
    }
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

    // Get PID
    UINT64 pid = (UINT64)PsGetCurrentProcessId();
    DbgPrint("FIREWALL: PID: %llu", pid);

    NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*)layerData);
    UINT16 oldSize = (UINT16)NET_BUFFER_DATA_LENGTH(netBuffer);
    UINT16 newSize = oldSize + 40;

    // STORAGE
    NetBufferListStorage *storage = (NetBufferListStorage*)ExAllocatePoolZero(POOL_FLAG_NON_PAGED, sizeof(NetBufferListStorage), NET_BUFFER_LIST_TAG);
    if (!storage)
    {
        DbgPrint("FIREWALL: ExAllocatePoolZero for 'storage' failed");
        return;
    }

    storage->oldBuffer = ExAllocatePoolZero(POOL_FLAG_NON_PAGED, oldSize, NET_BUFFER_LIST_TAG);;

    storage->ptr = ExAllocatePoolZero(POOL_FLAG_NON_PAGED, newSize, NET_BUFFER_LIST_TAG);
    if (!storage->ptr)
    {
        DbgPrint("FIREWALL: ExAllocatePoolWithTag for 'ptr' failed");
        return;
    }

    storage->mdl = IoAllocateMdl(storage->ptr, newSize, FALSE, FALSE, NULL);
    if (!storage->mdl)
    {
        DbgPrint("FIREWALL: IoAllocateMdl failed");
        return;
    }
    MmBuildMdlForNonPagedPool(storage->mdl);

    // Allocate new NetBufferList
    status = FwpsAllocateNetBufferAndNetBufferList(
        netBufferListHandle,
        0,
        0,
        storage->mdl,
        0,
        newSize,
        &storage->list
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("FIREWALL: FwpsAllocateNetBufferAndNetBufferList failed");
        return;
    }

    // Copy header

    BYTE* oldPacket = NdisGetDataBuffer(
        netBuffer,
        oldSize,
        storage->oldBuffer,
        1,
        0
    );
    if (oldPacket == NULL) {
        DbgPrint("FIREWALL: pFrame is NULL");
        return;
    }

    BYTE* newPacket = NdisGetDataBuffer(
        NET_BUFFER_LIST_FIRST_NB(storage->list),
        newSize,
        NULL,
        1,
        0);
    if (newPacket == NULL) {
        DbgPrint("FIREWALL: newPacket is NULL");
        return;
    }

    // Add 40 bytes of options
    RtlCopyMemory(newPacket, oldPacket, 20);
    RtlCopyMemory(newPacket + 60, oldPacket + 20, oldSize - 20);

    // Modify header size
    newPacket[0] = 0x4f;

    // Add actual options
    newPacket[20] = 130;
    newPacket[21] = 3;

    newPacket[22] = 0b11110001;

    newPacket[23] = 0xcd;
    newPacket[24] = 0xab;
    newPacket[25] = 1;

    newPacket[26] = 2;
    newPacket[27] = 34;
    newPacket[28] = 0;
    newPacket[29] = 0;
    //newPacket[28] = 0xab;

    for (int i = 23; i < 60; i++) {
        newPacket[i] = 0x00;
    }

    // Inject the new packet
    status = FwpsInjectNetworkSendAsync(
        injectionHandle,
        NULL,
        0,
        UNSPECIFIED_COMPARTMENT_ID,
        storage->list,
        FwpsInjectComplete,
        storage
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("FIREWALL: FwpsInjectNetworkSendAsync failed with status %x", status);
        return;
    }

    DbgPrint("FIREWALL: TLInspectIPPacketClassify - END");
}

NTSTATUS
TLInspectIPPacketNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    const FWPS_FILTER* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}
