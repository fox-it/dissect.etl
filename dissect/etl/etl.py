# Resources:
#   https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/callouts/hookid.htm
#   https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw // For most of the header definitions
#   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header // for timestamp calculation
#   https://docs.rs/winapi-ui-automation/0.3.9/winapi_ui_automation/um/evntcons/index.html
#   Windows Development Kit
#
# TMF parser:
#   https://searchcode.com/file/116783567/Tools/ETW/traceEvent/WPPTraceEventParser.cs
#
# Maybe interesting files to look at:
#   AppData\\Local\\Microsoft\\Windows\\Explorer\\ExplorerStartupLog.etl
#   Windows\\Performance\\WinSAT\\DataStore
#   Windows\\System32\\NDF\\*.etl
#   Windows\\System32\\LogFiles\\WMI
#   Windows\\System32\\SleepStudy
#   Windows\\Panther\\*.etl
#   Windows\\System32\\WDI\\LogFiles
from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict, Iterable, Optional
from uuid import UUID

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp

from dissect.etl import manifest
from dissect.etl.exceptions import (
    InvalidBufferError,
    InvalidHeaderError,
    ManifestNotFoundError,
)
from dissect.etl.headers.headers import Header
from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.headers.utils import select_event_header
from dissect.etl.utils import c_etl_definitions

c_etl = cstruct()
c_etl.load(c_etl_definitions)


class ETL:
    """The main interface when controlling an ETL file."""

    def __init__(self, fh):
        self.fh = fh

        # Load the first buffer inside the file,
        # The first event of the buffer contains a logfile header
        first_buffer = Buffer(self, 0)
        self.buffer_header = first_buffer.header
        trace_header = first_buffer.read_record(0).header
        self.logfile_header = LogfileHeader(trace_header)

        # Lookup PointerSize
        self.pointer_size = self.logfile_header.pointer_size

        if self.pointer_size not in (4, 8):
            raise InvalidHeaderError(f"invalid pointer size: {self.pointer_size}")

        self.is_64bit = self.logfile_header.is_64bit

        self.start_time = self.logfile_header.start_time
        self.buffer_size = self.buffer_header.BufferSize
        self.start = wintimestamp(self.logfile_header.start_time)
        self.end = wintimestamp(self.logfile_header.end_time)

        self._buffer_cache = {0: first_buffer}

    def buffer(self, index) -> Buffer:
        """Reads a specific buffer into memory."""

        if index < 0 or index >= self.logfile_header.buffers_written:
            raise IndexError("buffer index out of range")

        try:
            buf = self._buffer_cache[index]
        except KeyError:
            buf = Buffer(self, index * self.buffer_size)
            self._buffer_cache[index] = buf
        return buf

    def buffers(self) -> Iterable[Buffer]:
        for i in range(self.logfile_header.buffers_written):
            yield self.buffer(i)

    def __iter__(self) -> Iterable[Event]:
        for buffer in self.buffers():
            for event in buffer:
                yield event

    def calculate_timestamp(self, time_delta: int) -> datetime:
        return wintimestamp(self.get_filetime_for_event(time_delta))

    def get_filetime_for_event(self, time_delta: int) -> int:
        return self.logfile_header.timestamp_base + int(self._calculate_timescale_for_event(time_delta))

    def _calculate_timescale_for_event(self, time_delta: int) -> float:
        return self.logfile_header.timestamp_scale * time_delta


class Buffer:
    def __init__(self, etl, offset):
        self.fh = etl.fh
        self.etl = etl
        self.offset = offset

        self.fh.seek(offset)
        self.header = c_etl.BufferHeader(self.fh)

        self.data_size = self.header.Offset
        self.data_offset = self.fh.tell()
        data_len = self.data_size - (self.data_offset - offset)
        if data_len < 0:
            raise InvalidBufferError("Invalid data length")
        self.data = memoryview(self.fh.read(data_len))

    def __iter__(self) -> Iterable[EventRecord]:
        offset = 0
        while offset < self.data_size:
            try:
                event = self.read_record(offset)
                offset += event.aligned_size
                yield event
            except EOFError:
                break

    def read_record(self, offset):
        """Parse a record from a given offset inside a buffer."""

        event_record = EventRecord()
        data = self.data[offset:]
        header = select_event_header(
            data=data,
            etl=self.etl,
        )

        event_record._header = header

        return event_record

    def open(self):
        return io.BytesIO(self.data)


class EventRecord:
    __slots__ = (
        "_header",
        "_event",
    )

    def __init__(self):
        self._event = None
        self._header = None

    @property
    def header(self):
        """A header of the type Header"""
        return self._header

    @property
    def size(self):
        """Size of the whole record."""
        return self.header.size

    @property
    def event(self):
        """Parse payload inside the event header."""
        if not self._event:
            self._event = parse_payload(self._header)

        return self._event

    @property
    def Event(self):
        return self.event

    @property
    def aligned_size(self):
        return (self.size + 7) & 0xFFFFFFF8

    def __repr__(self):
        return "<EventRecord>"


class Event:
    __slots__ = [
        "_record",
        "_manifest",
        "_struct",
        "_event",
        "_header",
    ]

    def __init__(self, header: Header, event_manifest):
        self._header = header
        self._manifest = event_manifest
        self._event = None

        key = (header.opcode, header.version)
        if event_manifest:
            try:
                self._event = event_manifest.EVENTS[key]
                self._struct = self._event.template(header.payload)
            except KeyError:
                self._struct = None
        else:
            self._struct = None

    def __getattr__(self, k):
        try:
            return getattr(self._struct, k)
        except AttributeError:
            return object.__getattribute__(self, k)

    def provider_name(self) -> Optional[str]:
        """Returns the manifest provider name."""
        return self._manifest.PROVIDER_NAME if self._manifest else None

    def ts(self) -> datetime:
        """Returns the event timestamp."""
        return self._header.timestamp

    def provider_id(self) -> UUID:
        """Returns the GUID of the provider from the header."""
        return self._header.provider_id

    def symbol(self):
        return self._event.symbol if self._event else None

    def event_values(self) -> Dict[str, Any]:
        """Create an items view that holds event and header data.

        The header data is additional information provided from a specific header.
        The event data is from a specific manifest file if it exists.
        """
        event_values = self._header.additional_header_fields()
        struct_events = self._struct._values if self._struct else {}
        event_values.update(struct_events)
        return event_values

    def __repr__(self):
        symbol = self._event.symbol if self._event else None
        return f"{self._header} <{symbol} {self._struct!r}>"


def parse_payload(header: Header):
    """Parse the event payload using the appropriate manifest, if available."""

    try:
        mf = manifest.lookup(header.provider_id)
        if header.is_64bit:
            mf.c_parser.EtwPointer.as_64bit()
            mf.c_parser.UserSID_blob.as_64bit()
        else:
            mf.c_parser.EtwPointer.as_32bit()
            mf.c_parser.UserSID_blob.as_32bit()
    except (ManifestNotFoundError, AttributeError):
        mf = None

    return Event(header, mf)
