from io import BytesIO
from uuid import UUID

from dissect.cstruct import cstruct

c_global_def = """
#define EVENT_TRACE_GROUP_HEADER            0x0000
#define EVENT_TRACE_GROUP_IO                0x0100
#define EVENT_TRACE_GROUP_MEMORY            0x0200
#define EVENT_TRACE_GROUP_PROCESS           0x0300
#define EVENT_TRACE_GROUP_FILE              0x0400
#define EVENT_TRACE_GROUP_THREAD            0x0500
#define EVENT_TRACE_GROUP_TCPIP             0x0600
#define EVENT_TRACE_GROUP_JOB               0x0700
#define EVENT_TRACE_GROUP_UDPIP             0x0800
#define EVENT_TRACE_GROUP_REGISTRY          0x0900
#define EVENT_TRACE_GROUP_DBGPRINT          0x0A00
#define EVENT_TRACE_GROUP_CONFIG            0x0B00
#define EVENT_TRACE_GROUP_SPARE1            0x0C00
#define EVENT_TRACE_GROUP_WNF               0x0D00
#define EVENT_TRACE_GROUP_POOL              0x0E00
#define EVENT_TRACE_GROUP_PERFINFO          0x0F00
#define EVENT_TRACE_GROUP_HEAP              0x1000
#define EVENT_TRACE_GROUP_OBJECT            0x1100
#define EVENT_TRACE_GROUP_POWER             0x1200
#define EVENT_TRACE_GROUP_MODBOUND          0x1300
#define EVENT_TRACE_GROUP_IMAGE             0x1400
#define EVENT_TRACE_GROUP_DPC               0x1500
#define EVENT_TRACE_GROUP_CC                0x1600
#define EVENT_TRACE_GROUP_CRITSEC           0x1700
#define EVENT_TRACE_GROUP_STACKWALK         0x1800
#define EVENT_TRACE_GROUP_UMS               0x1900
#define EVENT_TRACE_GROUP_ALPC              0x1A00
#define EVENT_TRACE_GROUP_SPLITIO           0x1B00
#define EVENT_TRACE_GROUP_THREAD_POOL       0x1C00
#define EVENT_TRACE_GROUP_HYPERVISOR        0x1D00
#define EVENT_TRACE_GROUP_HYPERVISORX       0x1E00

#define EVENT_TRACE_TYPE_INFO               0x00  // Info or point event
#define EVENT_TRACE_TYPE_START              0x01  // Start event
#define EVENT_TRACE_TYPE_END                0x02  // End event
#define EVENT_TRACE_TYPE_STOP               0x02  // Stop event (WinEvent compatible)
#define EVENT_TRACE_TYPE_DC_START           0x03  // Collection start marker
#define EVENT_TRACE_TYPE_DC_END             0x04  // Collection end marker
#define EVENT_TRACE_TYPE_EXTENSION          0x05  // Extension/continuation
#define EVENT_TRACE_TYPE_REPLY              0x06  // Reply event
#define EVENT_TRACE_TYPE_DEQUEUE            0x07  // De-queue event
#define EVENT_TRACE_TYPE_RESUME             0x07  // Resume event (WinEvent compatible)
#define EVENT_TRACE_TYPE_CHECKPOINT         0x08  // Generic checkpoint event
#define EVENT_TRACE_TYPE_SUSPEND            0x08  // Suspend event (WinEvent compatible)
#define EVENT_TRACE_TYPE_WINEVT_SEND        0x09  // Send Event (WinEvent compatible)
#define EVENT_TRACE_TYPE_WINEVT_RECEIVE     0xF0  // Receive Event (WinEvent compatible)
"""
c_etl_global = cstruct()
c_etl_global.load(c_global_def)

c_etl_definitions = """
#define TRACE_HEADER_TYPE_SYSTEM32          0x01
#define TRACE_HEADER_TYPE_SYSTEM64          0x02
#define TRACE_HEADER_TYPE_COMPACT32         0x03
#define TRACE_HEADER_TYPE_COMPACT64         0x04
#define TRACE_HEADER_TYPE_FULL_HEADER32     0x0A
#define TRACE_HEADER_TYPE_INSTANCE32        0x0B
#define TRACE_HEADER_TYPE_TIMED             0x0C
#define TRACE_HEADER_TYPE_ERROR             0x0D
#define TRACE_HEADER_TYPE_WNODE_HEADER      0x0E
#define TRACE_HEADER_TYPE_MESSAGE           0x0F
#define TRACE_HEADER_TYPE_PERFINFO32        0x10
#define TRACE_HEADER_TYPE_PERFINFO64        0x11
#define TRACE_HEADER_TYPE_EVENT_HEADER32    0x12
#define TRACE_HEADER_TYPE_EVENT_HEADER64    0x13
#define TRACE_HEADER_TYPE_FULL_HEADER64     0x14
#define TRACE_HEADER_TYPE_INSTANCE64        0x15

struct SYSTEMTIME {
    WORD    wYear;
    WORD    wMonth;
    WORD    wDayOfWeek;
    WORD    wDay;
    WORD    wHour;
    WORD    wMinute;
    WORD    wSecond;
    WORD    wMilliseconds;
};

struct TimeZoneInformation {
    LONG        Bias;
    wchar       StandardName[32];
    SYSTEMTIME  StandardDate;
    LONG        StandardBias;
    wchar       DaylightName[32];
    SYSTEMTIME  DaylightDate;
    LONG        DaylightBias;
};

/* WMI_BUFFER_HEADER (latest)*/
struct BufferHeader {
    uint32  BufferSize;       /* 0x00 */
    uint32  SavedOffset;      /* 0x04 */
    uint32  CurrentOffset;    /* 0x08 */
    uint32  ReferenceCounter; /* 0x0C */
    uint64  TimeDelta;        /* 0x10 */
    int64   SequenceNumber;   /* 0x18 */
    uint64  Defined_1;        /* 0x20 */
    uint16  ProcessorIndex;   /* 0x28 ETW_BUFFER_CONTEXT */
    uint16  LoggerId;         /* 0x2A ETW_BUFFER_CONTEXT */
    uint32  ETW_BUFFER_STATE; /* 0x2C */
    uint32  Offset;           /* 0x30, Filled? */
    uint16  BufferFlag;       /* 0x34 */
    uint16  BufferType;       /* 0x36 */
    uint32  unk17;            /* 0x38 different for multiple iterations*/
    uint32  unk18;            /* 0x3C different for multiple iterations*/
    uint32  unk19;            /* 0x40 different for multiple iterations*/
    uint32  unk20;            /* 0x44 different for multiple iterations*/
};

/* TRACE_HEADER_TYPE_SYSTEM32, TRACE_HEADER_TYPE_SYSTEM64 */
struct SystemHeader {
    uint16  Version;            /* 0x00 */
    uint16  Marker;             /* 0x02 */
    uint16  Size;               /* 0x04 */
    uint8   OpCode;             /* 0x06 */
    uint8   Group;              /* 0x07 */
    uint32  ThreadId;           /* 0x08 */
    uint32  ProcessId;          /* 0x0c */
    uint64  TimeDelta;          /* 0x10 */
    uint64  ProcessorTime;      /* 0x18 */
};

/* TRACE_HEADER_TYPE_COMPACT32, TRACE_HEADER_TYPE_COMPACT64 */
struct CompactSystemHeader {
    uint16  Version;            /* 0x00 */
    uint16  Marker;             /* 0x02 */
    uint16  Size;               /* 0x04 */
    uint8   OpCode;             /* 0x06 */
    uint8   Group;              /* 0x07 */
    uint32  ThreadId;           /* 0x08 */
    uint32  ProcessId;          /* 0x0c */
    uint64  TimeDelta;          /* 0x10 */
};

/* TRACE_HEADER_TYPE_PERFINFO32, TRACE_HEADER_TYPE_PERFINFO64 */
struct PerformanceInfoHeader {
    uint16  Version;            /* 0x00 */
    uint16  Marker;             /* 0x02 */
    uint16  Size;               /* 0x04 */
    uint8   OpCode;             /* 0x06 */
    uint8   Group;              /* 0x07 */
    uint64  TimeDelta;          /* 0x10 */
};


/* TRACE_HEADER_TYPE_MESSAGE */
struct MessageHeader {
    uint16  Size;               /* 0x00 */
    uint16  Marker;             /* 0x02 */
    uint16  Id;                 /* 0x04 */
    uint16  EventProperty;      /* 0x06 */
};

/* TRACE_HEADER_TYPE_EVENT_HEADER32, TRACE_HEADER_TYPE_EVENT_HEADER64 */
struct EventHeader {
    uint16  Size;               /* 0x00 */
    uint16  Marker;             /* 0x02 */
    uint16  Flags;              /* 0x04 */
    uint16  EventProperty;      /* 0x06 */
    uint32  ThreadId;           /* 0x08 */
    uint32  ProcessId;          /* 0x0c */
    uint64  TimeDelta;          /* 0x10 */
    char    ProviderId[16];     /* 0x18 */
    uint16  Id;                 /* 0x28 */
    uint8   Version;            /* 0x2a */
    uint8   Channel;            /* 0x2b */
    uint8   Level;              /* 0x2c */
    uint8   OpCode;             /* 0x2d */
    uint16  Task;               /* 0x2e */
    uint64  Keywords;           /* 0x30 */
    uint64  ProcessorTime;      /* 0x38 */
    char    ActivityId[16];     /* 0x40 */
};

struct EventTraceHeader {
    uint16  Size;               /* 0x00 */
    uint16  Marker;             /* 0x02 */
    uint32  Version;            /* 0x04 */
    uint32  ThreadId;           /* 0x08 */
    uint32  ProcessId;          /* 0x0C */
    uint64  TimeDelta;          /* 0x10 */
    char    ProviderId[16];     /* 0x18 */
    uint32  KernelTime;         /* 0x28 */
    uint32  UserTime;           /* 0x2B*/
};

// An older header not used anymore
struct EventInstanceHeader {
    uint16  Size;
    uint16  Marker;
    uint32  Version;
    union {
        uint64  ThreadId;
        struct {
            uint32 ThreadId;
            uint32 ProcessId;
        } information;
    } ids;
    uint64  TimeDelta;
    uint64  RegHandle;
    uint32  InstanceId;
    uint32  ParentInstanceId;
    union {
        struct {
            uint32  KernelTime;
            uint32  UserTime;
        };
        uint64  ProcessorTime;
        struct {
            uint32  EventId;
            uint32  Flags;
        };
    };
    uint64  ParentRegHandle;
}

struct EventInstanceGUIDHeader {
    uint16  Size;
    uint16  Marker;
    uint32  Version;
    uint32  ThreadId;
    uint32  ProcessId;
    uint64  TimeDelta;
    char    ProviderId[16];
    union {
        struct {
            uint32  KernelTime;
            uint32  UserTime;
        } cpu_time;
        uint64  ProcessorTime;
        struct {
            uint32  EventId;
            uint32  Flags;
        } event_info;
    } event_metadata;
    uint32  InstanceId;
    uint32  ParentInstanceId;
    char    ParentGuid[16];
};


struct EventHeaderExtendedDataItemHeader {
    uint16  Size;
    uint16  ExtType;
    uint16  Reserved1;
    uint16  DataSize;
    char    Data[DataSize];
};

struct EVENT_HEADER_EXT_TYPE_ITEM_INSTANCE {
    uint32 InstanceId;
    uint32 ParentInstanceId;
    char ParentGuid[16];
};


struct EVENT_HEADER_EXT_TYPE_STACK_TRACE32 {
    uint64 MatchId;
    uint32 Address[];
};

struct EVENT_HEADER_EXT_TYPE_STACK_TRACE64 {
    uint64 MatchId;
    uint64 Address[];
};

struct TRAIT {
    uint16 TraitSize;           // Size of this individual trait including this field
    uint8  Type;                // ETW_PROVIDER_TRAIT_TYPE
    char   Data[TraitSize-3];   // Trait data
};

struct EVENT_HEADER_EXT_TYPE_PROVIDER_TRAIT {
    uint16 TraitSize;
    char   ProviderName[];
};


"""
c_etl_headers = cstruct()
c_etl_headers.load(c_etl_definitions)

NullGuid = UUID("{00000000-0000-0000-0000-000000000000}")
EventTraceGuid = UUID("{68fdd900-4a3e-11d1-84f4-0000f80464e3}")
DiskIoGuid = UUID("{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}")
PageFaultGuid = UUID("{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}")
ProcessGuid = UUID("{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}")
FileIoGuid = UUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}")
ThreadGuid = UUID("{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}")
TcpIpGuid = UUID("{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}")
JobGuid = UUID("{3282fc76-feed-498e-8aa7-e70f459d430e}")
UdpIpGuid = UUID("{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}")
RegistryGuid = UUID("{ae53722e-c863-11d2-8659-00c04fa321a1}")
DbgPrintGuid = UUID("{13976d09-a327-438c-950b-7f03192815c7}")
EventTraceConfigGuid = UUID("{01853a65-418f-4f36-aefc-dc0f1d2fd235}")
EventTraceSpare1 = UUID("{99134383-5248-43fc-834b-529454e75df3}")
WnfGuid = UUID("{42695762-ea50-497a-9068-5cbbb35e0b95}")
PoolGuid = UUID("{0268a8b6-74fd-4302-9dd0-6e8f1795c0cf}")
PerfinfoGuid = UUID("{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}")
HeapGuid = UUID("{222962ab-6180-4b88-a825-346b75f2a24a}")
ObjectGuid = UUID("{89497f50-effe-4440-8cf2-ce6b1cdcaca7}")
PowerGuid = UUID("{e43445e0-0903-48c3-b878-ff0fccebdd04}")
ModBoundGuid = UUID("{a9152f00-3f58-4bee-92a1-70c7d079d5dd}")
ImageLoadGuid = UUID("{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}")
DpcGuid = UUID("{b2d14872-7c5b-463d-8419-ee9bf7d23e04}")
CcGuid = UUID("{7687a439-f752-45b8-b741-321aec0f8df9}")
CritSecGuid = UUID("{3ac66736-cc59-4cff-8115-8df50e39816b}")
StackWalkGuid = UUID("{def2fe46-7bd6-4b80-bd94-f57fe20d0ce3}")
UmsEventGuid = UUID("{9aec974b-5b8e-4118-9b92-3186d8002ce5}")
ALPCGuid = UUID("{45d8cccd-539f-4b72-a8b7-5c683142609a}")
SplitIoGuid = UUID("{d837ca92-12b9-44a5-ad6a-3a65b3578aa8}")
ThreadPoolGuid = UUID("{c861d0e2-a2c1-4d36-9f9c-970bab943a12}")
HypervisorTraceGuid = UUID("{7f2a405c-69b5-4bf9-a1f5-30e8f1afab5e}")
HypervisorXTraceGuid = UUID("{2ce9a149-effe-42f0-a635-a1d39e26c8f2}")

GROUP_GUID_MAP = {
    c_etl_global.EVENT_TRACE_GROUP_HEADER: EventTraceGuid,
    c_etl_global.EVENT_TRACE_GROUP_IO: DiskIoGuid,
    c_etl_global.EVENT_TRACE_GROUP_MEMORY: PageFaultGuid,
    c_etl_global.EVENT_TRACE_GROUP_PROCESS: ProcessGuid,
    c_etl_global.EVENT_TRACE_GROUP_FILE: FileIoGuid,
    c_etl_global.EVENT_TRACE_GROUP_THREAD: ThreadGuid,
    c_etl_global.EVENT_TRACE_GROUP_TCPIP: TcpIpGuid,
    c_etl_global.EVENT_TRACE_GROUP_JOB: JobGuid,
    c_etl_global.EVENT_TRACE_GROUP_UDPIP: UdpIpGuid,
    c_etl_global.EVENT_TRACE_GROUP_REGISTRY: RegistryGuid,
    c_etl_global.EVENT_TRACE_GROUP_DBGPRINT: DbgPrintGuid,
    c_etl_global.EVENT_TRACE_GROUP_CONFIG: EventTraceConfigGuid,
    c_etl_global.EVENT_TRACE_GROUP_SPARE1: EventTraceSpare1,
    c_etl_global.EVENT_TRACE_GROUP_WNF: WnfGuid,
    c_etl_global.EVENT_TRACE_GROUP_POOL: PoolGuid,
    c_etl_global.EVENT_TRACE_GROUP_PERFINFO: PerfinfoGuid,
    c_etl_global.EVENT_TRACE_GROUP_HEAP: HeapGuid,
    c_etl_global.EVENT_TRACE_GROUP_OBJECT: ObjectGuid,
    c_etl_global.EVENT_TRACE_GROUP_POWER: PowerGuid,
    c_etl_global.EVENT_TRACE_GROUP_MODBOUND: ModBoundGuid,
    c_etl_global.EVENT_TRACE_GROUP_IMAGE: ImageLoadGuid,
    c_etl_global.EVENT_TRACE_GROUP_DPC: DpcGuid,
    c_etl_global.EVENT_TRACE_GROUP_CC: CcGuid,
    c_etl_global.EVENT_TRACE_GROUP_CRITSEC: CritSecGuid,
    c_etl_global.EVENT_TRACE_GROUP_STACKWALK: StackWalkGuid,
    c_etl_global.EVENT_TRACE_GROUP_UMS: UmsEventGuid,
    c_etl_global.EVENT_TRACE_GROUP_ALPC: ALPCGuid,
    c_etl_global.EVENT_TRACE_GROUP_SPLITIO: SplitIoGuid,
    c_etl_global.EVENT_TRACE_GROUP_THREAD_POOL: ThreadPoolGuid,
    c_etl_global.EVENT_TRACE_GROUP_HYPERVISOR: HypervisorTraceGuid,
    c_etl_global.EVENT_TRACE_GROUP_HYPERVISORX: HypervisorXTraceGuid,
}


def lookup_guid(group, opcode):
    # Magic number were grabbed by reverse engineering sechost.dll
    # https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/callouts/hookid.htm
    lookup = group
    if lookup == 3 and opcode == 10:
        lookup = 20

    if lookup >= 31:
        return NullGuid

    return GROUP_GUID_MAP[lookup << 8]


def bytes_left(stream: BytesIO):
    """Get number of bytes left in the buffer."""
    return stream.getbuffer().nbytes - stream.tell()
