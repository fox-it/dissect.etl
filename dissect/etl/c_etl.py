from __future__ import annotations

from dissect.cstruct import cstruct

global_def = """
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
c_etl_global = cstruct().load(global_def)

etl_def = """
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

flag ETW_BUFFER_FLAG: uint16 {
    NORMAL           = 0x0000
    FLUSH_MARKER     = 0x0001
    EVENTS_LOST      = 0x0002
    BUFFER_LOST      = 0x0004
    RTBACKUP_CORRUPT = 0x0008
    RTBACKUP         = 0x0010
    PROC_INDEX       = 0x0020
    COMPRESSED  = 0x0040
};

enum ETW_BUFFER_TYPE: uint16 {
    GENERIC      = 0x0000
    RUNDOWN      = 0x0001
    CTX_SWAP     = 0x0002
    REFTIME      = 0x0003
    HEADER       = 0x0004
    BATCHED      = 0x0005
    EMPTY_MARKER = 0x0006
    DBG_INFO     = 0x0007
    MAXIMUM      = 0x0008
};

/* WMI_BUFFER_HEADER (latest)*/
struct BufferHeader {
    uint32           BufferSize;       /* 0x00 */
    uint32           SavedOffset;      /* 0x04 */
    uint32           CurrentOffset;    /* 0x08 */
    uint32           ReferenceCounter; /* 0x0C */
    uint64           TimeDelta;        /* 0x10 */
    int64            SequenceNumber;   /* 0x18 */
    uint64           Defined_1;        /* 0x20 */
    uint16           ProcessorIndex;   /* 0x28 ETW_BUFFER_CONTEXT */
    uint16           LoggerId;         /* 0x2A ETW_BUFFER_CONTEXT */
    uint32           ETW_BUFFER_STATE; /* 0x2C */
    uint32           FilledBytes;      /* 0x30, Filled bytes inside the buffer. */
    ETW_BUFFER_FLAG  BufferFlag;       /* 0x34 */
    ETW_BUFFER_TYPE  BufferType;       /* 0x36 */
    uint32           unk17;            /* 0x38 different for multiple iterations*/
    uint32           unk18;            /* 0x3C different for multiple iterations*/
    uint32           unk19;            /* 0x40 different for multiple iterations*/
    uint32           unk20;            /* 0x44 different for multiple iterations*/
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
c_etl = cstruct().load(etl_def)

# Flags and enumerations
BufferType = c_etl.ETW_BUFFER_TYPE
BufferFlag = c_etl.ETW_BUFFER_FLAG
