from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from dissect.etl.c_etl import c_etl_global

if TYPE_CHECKING:
    from io import BytesIO

# Known UUIDs
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


def lookup_guid(group: int, opcode: int) -> UUID:
    # Magic number were grabbed by reverse engineering sechost.dll
    # https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/callouts/hookid.htm
    lookup = group
    if lookup == 3 and opcode == 10:
        lookup = 20

    if lookup >= 31:
        return NullGuid

    return GROUP_GUID_MAP[lookup << 8]


def bytes_left(stream: BytesIO) -> int:
    """Get number of bytes left in the buffer."""
    return stream.getbuffer().nbytes - stream.tell()
