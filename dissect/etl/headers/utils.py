from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.etl.c_etl import c_etl
from dissect.etl.exceptions import NoMoreEventsError
from dissect.etl.headers.event import EventHeader
from dissect.etl.headers.headers import (
    ErrorHeader,
    EventInstanceGUIDHeader,
    EventTraceHeader,
    Header,
    InvalidHeader,
    Marker,
    MessageTraceHeader,
    UnimplementedHeader,
)
from dissect.etl.headers.system import (
    CompactSystemHeader,
    PerfinfoTraceHeader,
    SystemHeader,
)

if TYPE_CHECKING:
    from dissect.etl.etl import ETL

HEADERS: dict[int, Header] = {
    c_etl.TRACE_HEADER_TYPE_SYSTEM32: SystemHeader,
    c_etl.TRACE_HEADER_TYPE_SYSTEM64: SystemHeader,
    c_etl.TRACE_HEADER_TYPE_COMPACT32: CompactSystemHeader,
    c_etl.TRACE_HEADER_TYPE_COMPACT64: CompactSystemHeader,
    c_etl.TRACE_HEADER_TYPE_FULL_HEADER32: EventTraceHeader,
    c_etl.TRACE_HEADER_TYPE_INSTANCE32: EventInstanceGUIDHeader,
    c_etl.TRACE_HEADER_TYPE_TIMED: UnimplementedHeader,
    c_etl.TRACE_HEADER_TYPE_ERROR: ErrorHeader,
    c_etl.TRACE_HEADER_TYPE_WNODE_HEADER: UnimplementedHeader,
    c_etl.TRACE_HEADER_TYPE_MESSAGE: MessageTraceHeader,
    c_etl.TRACE_HEADER_TYPE_PERFINFO32: PerfinfoTraceHeader,
    c_etl.TRACE_HEADER_TYPE_PERFINFO64: PerfinfoTraceHeader,
    c_etl.TRACE_HEADER_TYPE_EVENT_HEADER32: EventHeader,
    c_etl.TRACE_HEADER_TYPE_EVENT_HEADER64: EventHeader,
    c_etl.TRACE_HEADER_TYPE_FULL_HEADER64: EventTraceHeader,
    c_etl.TRACE_HEADER_TYPE_INSTANCE64: EventInstanceGUIDHeader,
}


def select_event_header(data: memoryview, etl: ETL) -> Header:
    """Select event header with marker"""
    marker_int = c_etl.uint32(data[:4])

    if marker_int == 0xFFFFFFFF:
        # In this case, we reached the padding inside a buffer.
        # WHich marks it as the end of data.
        raise NoMoreEventsError("We are at the end of the events inside the buffer.")

    marker = Marker(marker_int)
    header = HEADERS.get(marker.header_type, InvalidHeader)

    return header(marker, data, etl)
