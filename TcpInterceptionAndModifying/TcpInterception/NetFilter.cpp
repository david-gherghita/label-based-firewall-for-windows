#include "pch.h"
#include "NetFilter.h"

//#include "winsock.h"
//#include "stdint.h"

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))

// {B8F58E09-BA43-4837-9723-AD80258E8C0A}
DEFINE_GUID(INTERCEPTION_SUBLAYER, 0xb8f58e09, 0xba43, 0x4837, 0x97, 0x23, 0xad, 0x80, 0x25, 0x8e, 0x8c, 0xa);

// {47896A45-35FB-4EFF-92D5-5BC8A91343C3}
DEFINE_GUID(INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT, 0x47896a45, 0x35fb, 0x4eff, 0x92, 0xd5, 0x5b, 0xc8, 0xa9, 0x13, 0x43, 0xc3);

#define NET_BUFFER_LIST_STORAGE_TAG      'gTlB'
#define NET_BUFFER_LIST_PTR_TAG          'gTtP'
#define SEND_PARAMETERS_TAG              'gTpS'
#define TCP_HEADER_STORAGE_TAG           'rotS'
#define HASH_TAG                         'hsaH'

static UINT16
ntohs(UINT16 val)
{
    UINT16 b1 = (val >> 8) & 0xff;
    UINT16 b2 = (val >> 0) & 0xff;

    return (b2 << 8) | b1;
}



static UINT32
ntohl(UINT32 val)
{
    UINT16 b1 = (val >> 24) & 0xff;
    UINT16 b2 = (val >> 16) & 0xff;
    UINT16 b3 = (val >> 8) & 0xff;
    UINT16 b4 = (val >> 0) & 0xff;



    return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
}

const wchar_t g_displayName[] = L"TCP Interception Filter";

static BCRYPT_ALG_HANDLE hAlg;

struct SendParameters
{
    IN_ADDR                    addr;
    FWPS_TRANSPORT_SEND_PARAMS params;
};

struct NetworkBufferListStorage
{
    NDIS_HANDLE             handle;
    PVOID                   ptr;
    PMDL                    mdl;
    PNET_BUFFER_LIST        list;
    SendParameters*         params;
};

static HANDLE g_engineHandle = nullptr;
static NDIS_HANDLE g_netBufferListHandle = nullptr;
static HANDLE g_injectionHandle = nullptr;
static UINT32 g_id = 0;

static void FreeNetworkBufferListStorage(NetworkBufferListStorage* storage)
{
    if (!storage)
    {
        return;
    }

    if (storage->ptr)
    {
        ExFreePoolWithTag(storage->ptr, NET_BUFFER_LIST_PTR_TAG);
    }

    if (storage->mdl)
    {
        IoFreeMdl(storage->mdl);
    }

    if (storage->list)
    {
        FwpsFreeNetBufferList(storage->list);
    }

    if (storage->params)
    {
        ExFreePoolWithTag(storage->params, SEND_PARAMETERS_TAG);
    }

    ExFreePoolWithTag(storage, NET_BUFFER_LIST_STORAGE_TAG);
}

static void CompleteCallback(PVOID context,
    PNET_BUFFER_LIST /*netBufferList*/,
    BOOLEAN /*dispatchLevel*/
)
{
    FreeNetworkBufferListStorage(reinterpret_cast<NetworkBufferListStorage*>(context));
}

static NTSTATUS InitializeNetworkBufferListStorage(NetworkBufferListStorage& storage,
    SendParameters* params,
    ULONG size)
{
    storage.ptr = ExAllocatePoolZero(NonPagedPoolNx,
        size,
        NET_BUFFER_LIST_PTR_TAG);
    if (!storage.ptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    storage.mdl = IoAllocateMdl(storage.ptr, size, false, false, nullptr);
    if (!storage.mdl)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(storage.mdl);

    NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList(g_netBufferListHandle,
        0,
        0,
        storage.mdl,
        0,
        size,
        &storage.list);
    if (NT_SUCCESS(status))
    {
        storage.params = params;
    }

    return status;
}

static NetworkBufferListStorage* CreateNetworkBufferListStorage(ULONG size, SendParameters* params)
{
    auto netBufferStorage = reinterpret_cast<NetworkBufferListStorage*>(ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(NetworkBufferListStorage),
        NET_BUFFER_LIST_STORAGE_TAG));
    if (!netBufferStorage)
    {
        return nullptr;
    }

    NTSTATUS status = InitializeNetworkBufferListStorage(*netBufferStorage, params, size);
    if (!NT_SUCCESS(status))
    {
        FreeNetworkBufferListStorage(netBufferStorage);
        netBufferStorage = nullptr;
    }

    return netBufferStorage;
}

static SendParameters* CreateSendParameters(const SCOPE_ID& scopeId, UINT32 address)
{
     auto params = reinterpret_cast<SendParameters*>(ExAllocatePoolZero(NonPagedPoolNx,
        sizeof(SendParameters),
        SEND_PARAMETERS_TAG));

    if (!params)
    {
        return nullptr;
    }

    RtlZeroMemory(params, sizeof(SendParameters));

    params->params.remoteAddress = reinterpret_cast<UCHAR*>(&params->addr);
    params->params.remoteScopeId = scopeId;
    params->addr.S_un.S_addr = _byteswap_ulong(address);

    return params;
}

static void SignPacket(unsigned char* packet, unsigned int dataSize)
{
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbHash = 0;
    DWORD                   cbHashObject = 0;
    DWORD                   cbData = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL;
    PBYTE                   pbInputData = NULL;
    CONST BYTE key[] = { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x66irewall" };

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptGetProperty\n", status);
        return;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)ExAllocatePoolZero(
        NonPagedPoolNx,
        cbHashObject,
        HASH_TAG);
    if (NULL == pbHashObject)
    {
        DbgPrint("FIREWALL: **** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)ExAllocatePoolZero(
        NonPagedPoolNx,
        cbHash,
        HASH_TAG);
    if (NULL == pbHash)
    {
        DbgPrint("FIREWALL: **** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        (PBYTE)key,
        sizeof(key) - 1,
        0)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }

    //allocate the buffer for the hash input data
    pbInputData = (PBYTE)ExAllocatePoolZero(
        NonPagedPoolNx,
        dataSize + 4,
        HASH_TAG);
    if (NULL == pbInputData)
    {
        DbgPrint("FIREWALL: **** memory allocation for input data failed\n");
        goto Cleanup;
    }

    RtlCopyMemory(pbInputData, packet + 4, 4); // Copy SEQ
    RtlCopyMemory(pbInputData + 4, packet + 60, dataSize); // Copy payload

    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(
        hHash,
        pbInputData,
        dataSize + 4,
        0)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    RtlCopyMemory(packet + 28, pbHash, 32);

    DbgPrint("FIREWALL: %2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X",
        pbHash[0], pbHash[1], pbHash[2], pbHash[3], pbHash[4], pbHash[5], pbHash[6], pbHash[7], pbHash[8], pbHash[9], pbHash[10], pbHash[11], pbHash[12], pbHash[13], pbHash[14], pbHash[15],
        pbHash[16], pbHash[17], pbHash[18], pbHash[19], pbHash[20], pbHash[21], pbHash[22], pbHash[23], pbHash[24], pbHash[25], pbHash[26], pbHash[27], pbHash[28], pbHash[29], pbHash[30], pbHash[31]);

Cleanup:

    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject)
    {
        ExFreePoolWithTag(pbHashObject, HASH_TAG);
    }

    if (pbHash)
    {
        ExFreePoolWithTag(pbHash, HASH_TAG);
    }

    if (pbInputData)
    {
        ExFreePoolWithTag(pbInputData, HASH_TAG);
    }
};

static NTSTATUS InsertUpdatedTcpPacket(NetworkBufferListStorage& storage,
    BYTE* origTcpHeader,
    ULONG origTcpHeaderSize,
    ULONG newTcpHeaderSize,
    ULONG dataSize,
    UINT64 endpointHandle,
    COMPARTMENT_ID compId)
{
    for (PNET_BUFFER pBuf = NET_BUFFER_LIST_FIRST_NB(storage.list); pBuf; pBuf = NET_BUFFER_NEXT_NB(pBuf))
    {
        BYTE* newTcpHeader = (BYTE*)NdisGetDataBuffer(pBuf,
            newTcpHeaderSize,
            nullptr,
            1,
            0);
        if (!newTcpHeader)
        {
            return STATUS_UNSUCCESSFUL;
        }

        // Copy standard header
        RtlCopyMemory(newTcpHeader, origTcpHeader, 20);

        // Copy data bytes
        RtlCopyMemory(newTcpHeader + 60, origTcpHeader + origTcpHeaderSize, dataSize);

        // Set new Header Size and preserve flags
        ((BYTE*)newTcpHeader)[12] |= 0b11110000;

        //DbgPrint("FIREWALL: New packet");
        //DbgPrint("FIREWALL: sport: %u dport: %u SEQ: %u, ACK: %u", ntohs(*(UINT16*)newTcpHeader), ntohs(*(UINT16*)(newTcpHeader + 2)), ntohl(*(UINT32*)(newTcpHeader + 4)), ntohl(*(UINT32*)(newTcpHeader + 8)));
        //DbgPrint("FIREWALL: syn: %x", newTcpHeader[13] & 0b00000010);
        //DbgPrint("FIREWALL: ack: %x", newTcpHeader[13] & 0b00010000);
        //DbgPrint("FIREWALL: fin: %x", newTcpHeader[13] & 0b00000001);
        //if (dataSize != 0)
        //    DbgPrint("FIREWALL: Data: %c", *(BYTE*)(newTcpHeader + 60));

        unsigned char* extraOptions = reinterpret_cast<unsigned char*>(Add2Ptr(newTcpHeader, 20));
        // Codepoint / Kind
        extraOptions[0] = 253;
        // Length including Kind and length fields
        extraOptions[1] = 40;
        // ID
        extraOptions[2] = 0x46;
        extraOptions[3] = 0x77;
        for (int i = 4; i < 8; i++) {
            extraOptions[i] = 0;
        }

        SignPacket(newTcpHeader, dataSize);

        FwpsInjectTransportSendAsync(g_injectionHandle,
            nullptr,
            endpointHandle,
            0,
            &storage.params->params,
            AF_INET,
            compId,
            storage.list,
            CompleteCallback,
            &storage);
    }
    return 0;
}

static void ProcessTransportData(const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    const auto injectionState = FwpsQueryPacketInjectionState0(g_injectionHandle,
        static_cast<NET_BUFFER_LIST*>(layerData),
        nullptr);

    // Skip packets injected by our driver
    if (FWPS_PACKET_INJECTED_BY_SELF == injectionState ||
        FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF == injectionState)
    {
        return;
    }

    // Get PID
    // UINT64 pid = (UINT64)PsGetCurrentProcessId();
    // DbgPrint("FIREWALL: PID: %llu", pid);

    NET_BUFFER_LIST* netBufferList = static_cast<NET_BUFFER_LIST*>(layerData);

    int counter = -1;
    for (NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList); netBuffer; netBuffer = NET_BUFFER_NEXT_NB(netBuffer))
    {   
        counter += 1;
        // Need to block and absorb current packet to inject new packet with options
        classifyOut->actionType = FWP_ACTION_BLOCK;
        SetFlag(classifyOut->flags, FWPS_CLASSIFY_OUT_FLAG_ABSORB);

        auto sendParams = CreateSendParameters(inMetaValues->remoteScopeId,
            inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
        if (!sendParams)
        {
            return;
        }

        static const int extraOptionSize = 40;
        // IF TCP
        if (inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8 == 6) {
            PVOID origTcpHeaderStorage = ExAllocatePoolZero(NonPagedPoolNx, NET_BUFFER_DATA_LENGTH(netBuffer), TCP_HEADER_STORAGE_TAG);
            BYTE* origTcpHeader = (BYTE*)NdisGetDataBuffer(netBuffer, NET_BUFFER_DATA_LENGTH(netBuffer), origTcpHeaderStorage, 1, 0);
            BYTE origTcpHeaderSize = ((((BYTE*)origTcpHeader)[12] & 0b11110000) >> 4) * 4;
            ULONG dataSize = NET_BUFFER_DATA_LENGTH(netBuffer) - origTcpHeaderSize;


            DbgPrint("FIREWALL: New packet");
            DbgPrint("FIREWALL: sport: %u dport: %u SEQ: %u, ACK: %u", ntohs(*(UINT16*)origTcpHeader), ntohs(*(UINT16*)(origTcpHeader + 2)), ntohl(*(UINT32*)(origTcpHeader + 4)), ntohl(*(UINT32*)(origTcpHeader + 8)));
            DbgPrint("FIREWALL: syn: %x", origTcpHeader[13] & 0b00000010);
            DbgPrint("FIREWALL: ack: %x", origTcpHeader[13] & 0b00010000);
            DbgPrint("FIREWALL: fin: %x", origTcpHeader[13] & 0b00000001);
            UCHAR header_size = (origTcpHeader[12] >> 4) * 4;
            if (dataSize != 0)
                DbgPrint("FIREWALL: Data: %c", *(BYTE*)(origTcpHeader + header_size));


            // TCP header size should be aligned in the 32-bit words
            const ULONG newTcpHeaderSize = extraOptionSize + dataSize + 20;

            // Need to allocate new NET_BUFFER_LIST for new packet with new TCP header
            auto netBufferListStorage = CreateNetworkBufferListStorage(newTcpHeaderSize, sendParams);
            if (!netBufferListStorage)
            {
                ExFreePoolWithTag(sendParams, SEND_PARAMETERS_TAG);
                return;
            }
            sendParams = nullptr;

            NTSTATUS status = InsertUpdatedTcpPacket(*netBufferListStorage,
                origTcpHeader,
                origTcpHeaderSize,
                newTcpHeaderSize,
                dataSize,
                inMetaValues->transportEndpointHandle,
                static_cast<COMPARTMENT_ID>(inMetaValues->compartmentId));
            if (!NT_SUCCESS(status))
            {
                DbgPrint("FIREWALL: InsertUpdatedTcpPacket failed with %x", status);
            }

            // Free data
            if (sendParams) {
                ExFreePoolWithTag(sendParams, SEND_PARAMETERS_TAG);
            }
            if (origTcpHeaderStorage) {
                ExFreePoolWithTag(origTcpHeaderStorage, TCP_HEADER_STORAGE_TAG);
            }

        } // ELSE IF UDP
        else {//if (inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8 == 17) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
        }
    }
}

static void CalloutConnectClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const FWPS_FILTER0* filter,
    UINT64 /*flowContext*/,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    // Allowing the traffic for another filter to make a final decision.
    if (FlagOn(classifyOut->rights, FWPS_RIGHT_ACTION_WRITE))
    {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (layerData)
    {
        ProcessTransportData(inFixedValues, inMetaValues, layerData, classifyOut);
    }

    // Callout function should clear the FWPS_RIGHT_ACTION_WRITE flag when it returns FWP_ACTION_BLOCK for the suggested action
    // and if FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT flag is set
    if (FWP_ACTION_BLOCK == classifyOut->actionType || FlagOn(filter->flags, FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT))
    {
        ClearFlag(classifyOut->rights, FWPS_RIGHT_ACTION_WRITE);
    }
}

static NTSTATUS CalloutNotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE /*notifyType*/,
    const GUID* /*filterKey*/,
    FWPS_FILTER0* /*filter*/)
{
    return STATUS_SUCCESS;
}

static NTSTATUS InitializeCallout(PDEVICE_OBJECT deviceObject)
{
    FWPM_SUBLAYER subLayer = {};
    subLayer.displayData.name = const_cast<wchar_t*>(L"TcpInterception Sub-Layer");
    subLayer.subLayerKey = INTERCEPTION_SUBLAYER;

    NTSTATUS status = FwpmSubLayerAdd(g_engineHandle, &subLayer, nullptr);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FWPS_CALLOUT0 sCallout =
    {
        INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT,
        0,
        CalloutConnectClassifyFn,
        CalloutNotifyFn,
        nullptr
    };

    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_id);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FWPM_CALLOUT mCallout = {};
    mCallout.calloutKey = INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT;
    mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    mCallout.displayData.name = const_cast<wchar_t*>(g_displayName);

    status = FwpmCalloutAdd(g_engineHandle, &mCallout, nullptr, nullptr);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FWPM_FILTER filter = {};
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.displayData.name = const_cast<wchar_t*>(g_displayName);;
    filter.displayData.description = filter.displayData.name;

    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT;
    filter.numFilterConditions = 0;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_EMPTY;

    status = FwpmFilterAdd(g_engineHandle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = FwpsInjectionHandleCreate(AF_UNSPEC, 0, &g_injectionHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return status;
}

NTSTATUS InitializeFilter(PDEVICE_OBJECT deviceObject)
{
    NTSTATUS status;

    // HMAC
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_PROV_DISPATCH)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptOpenAlgorithmProvider 1", status);
        return STATUS_FAILED_DRIVER_ENTRY;
    }
    else {
        DbgPrint("FIREWALL: BCryptOpenAlgorithmProvider Success 1");
    }
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_PROV_DISPATCH | BCRYPT_ALG_HANDLE_HMAC_FLAG)))
    {
        DbgPrint("FIREWALL: **** Error 0x%x returned by BCryptOpenAlgorithmProvider 2", status);
        return STATUS_FAILED_DRIVER_ENTRY;
    }
    else {
        DbgPrint("FIREWALL: BCryptOpenAlgorithmProvider Success 2");
    }

    FWPM_SESSION session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &g_engineHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Need to allocate NET_BUFFER_LIST pool to create NET_BUFFER_LISTs for new packets
    NET_BUFFER_LIST_POOL_PARAMETERS netBufferListParameters = {};
    netBufferListParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    netBufferListParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    netBufferListParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    netBufferListParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    netBufferListParameters.PoolTag = 'IpcT';
    // NdisAllocateNetBufferAndNetBufferList can be called only if fAllocateNetBuffer is TRUE and DataSize is zero.
    netBufferListParameters.DataSize = 0;
    netBufferListParameters.fAllocateNetBuffer = TRUE;

    g_netBufferListHandle = NdisAllocateNetBufferListPool(nullptr, &netBufferListParameters);
    if (!g_netBufferListHandle)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = FwpmTransactionBegin(g_engineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = InitializeCallout(deviceObject);
    if (NT_SUCCESS(status))
    {
        FwpmTransactionCommit(g_engineHandle);
    }
    else
    {
        FwpmTransactionAbort(g_engineHandle);
    }

    return status;
}

void DeinitializeFilter()
{
    if (g_id)
    {
        FwpsCalloutUnregisterById(g_id);
    }

    if (g_injectionHandle)
    {
        FwpsInjectionHandleDestroy(g_injectionHandle);
    }

    if (g_netBufferListHandle)
    {
        NdisFreeNetBufferListPool(g_netBufferListHandle);
    }

    if (g_engineHandle)
    {
        FwpmEngineClose(g_engineHandle);
        g_engineHandle = nullptr;
    }
}