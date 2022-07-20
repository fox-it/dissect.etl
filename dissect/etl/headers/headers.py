from abc import abstractmethod
from datetime import datetime
from enum import IntEnum
from io import BytesIO
from typing import Any, Dict
from uuid import UUID

from dissect.cstruct.types.structure import Structure

from dissect.etl.exceptions import InvalidHeaderError, InvalidMarkerError
from dissect.etl.utils import bytes_left, c_etl_headers

BIT64_HEADERS = [
    c_etl_headers.TRACE_HEADER_TYPE_SYSTEM64,
    c_etl_headers.TRACE_HEADER_TYPE_COMPACT64,
    c_etl_headers.TRACE_HEADER_TYPE_PERFINFO64,
    c_etl_headers.TRACE_HEADER_TYPE_EVENT_HEADER64,
    c_etl_headers.TRACE_HEADER_TYPE_FULL_HEADER64,
    c_etl_headers.TRACE_HEADER_TYPE_INSTANCE64,
]


class Marker:
    """Abstracts the marker calculation for headers."""

    MARKER_MASK = 0xFF000000
    HEADER_MASK = 0x00FF0000
    REMAINDER_MASK = 0x0000FFFF

    MESSAGE_FLAGS = 0x90
    HEADER_FLAGS = 0xC0

    def __init__(self, marker: int):
        self.marker = marker

    @property
    def flags(self):
        return (self.marker & self.MARKER_MASK) >> 24

    @property
    def header_type(self):
        if self.flags == self.HEADER_FLAGS:
            return (self.marker & self.HEADER_MASK) >> 16
        elif self.flags == self.MESSAGE_FLAGS:
            return c_etl_headers.TRACE_HEADER_TYPE_MESSAGE
        else:
            raise InvalidMarkerError("Unknown flags combination")

    @property
    def remainder(self):
        return self.marker & self.REMAINDER_MASK


class Header:
    """A baseclass for the different ETL headers."""

    def __init__(self, marker: Marker, data: memoryview, etl):
        self._etl = etl
        self._marker = marker
        self._header = None
        self._payload = None
        self.data = data

        if self.size < self.minimal_size:
            raise InvalidHeaderError(
                f"Size too small for record type 0x{self._marker.header_type:02x}"
                f" from marker 0x{self.marker:08x} ({self.size} < {self.minimal_size}"
            )

    @property
    @abstractmethod
    def minimal_size(self) -> int:
        """Minimum header size."""
        pass

    @property
    @abstractmethod
    def _header_type(self) -> Structure:
        """Type of header that will get parsed."""
        pass

    @property
    def provider_id(self) -> UUID:
        """Provider that generated this event."""
        return UUID(bytes_le=self.header.ProviderId)

    @property
    def version(self) -> int:
        """The version of the event."""
        return self.header.Version

    @property
    def timestamp(self) -> datetime:
        """The timestamp of the event."""
        return self._etl.calculate_timestamp(self.time_delta)

    @property
    def time_delta(self) -> int:
        """The change in time relative to the start of the logfile."""
        return self.header.TimeDelta

    @property
    def marker(self) -> int:
        """The marker data for this event."""
        return self._marker.marker

    @property
    def is_64bit(self) -> bool:
        """A value to determine if the header is 64 or 32 bits."""
        return self._marker.header_type in BIT64_HEADERS

    @property
    def size(self) -> int:
        """The size of the event.

        In most cases this is inside the remainder field of the marker.
        """
        return self._marker.remainder

    @property
    def data_size(self) -> int:
        """The size of the payload."""
        return self.size - self.minimal_size

    @property
    def payload(self) -> memoryview:
        """Grab the payload data from the datastream."""
        if not self._payload:
            self._payload = self.data[self.minimal_size : self.size]
        return self._payload

    @property
    def header(self) -> Structure:
        """Type of header that will get parsed."""
        if not self._header:
            self._header = self._header_type(self.data[: self.minimal_size])
        return self._header

    @abstractmethod
    def additional_header_fields(self) -> Dict[str, Any]:
        """Additional fields that hold interesting information.

        each header subclass defines what additional information it wants to return to a record."""
        pass

    def standard_header_fields(self) -> Dict[str, Any]:
        """Some standard header information that can be retrieved for any header."""
        standard_fields = {
            "version": self.version,
            "provider_id": self.provider_id,
            "timestamp": self.timestamp,
        }
        return standard_fields

    def __repr__(self):
        standard_output = " ".join(f"{key}={value}" for key, value in self.standard_header_fields().items())
        additional_output = " ".join(f"{key}={value}" for key, value in self.additional_header_fields().items())
        return f"<{self.__class__.__name__} {standard_output} {additional_output}>"


class InvalidHeader(Header):
    """An invalid header."""

    def __init__(self, marker, data, etl):
        raise InvalidHeaderError()


class UnimplementedHeader(Header):
    """A header that isn't implemented yet."""

    pass


class EventProperty(IntEnum):
    """Defines what the message trace header can additionally find in its payload."""

    SEQUENCE = 0x0001
    GUID = 0x0002
    COMPONENT_ID = 0x0004
    TIMESTAMP = 0x0008
    PERFORMANCE_TIMESTAMP = 0x0010
    SYSTEMINFO = 0x0020
    POINTER32 = 0x0040
    POINTER64 = 0x0080


class MessageTraceHeader(Header):
    def __init__(self, marker: Marker, data: memoryview, etl):
        super().__init__(marker, data, etl)
        self.payload_offset = 0
        self.opcode = None
        self._thread_id = None
        self._process_id = None
        self._sequence_number = None
        self._provider_id = None
        self._time_delta = None
        self._parse_event_properties()

    @property
    def minimal_size(self) -> int:
        return 0x8

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.MessageHeader

    def _parse_event_properties(self):
        payload = BytesIO(self.payload)

        if self.event_property & EventProperty.SEQUENCE:
            self._sequence_number = c_etl_headers.uint32(payload)

        if self._contains_provider_id(payload):
            self._provider_id = UUID(bytes_le=payload.read(16))

        if bytes_left(payload) >= 8 and self.event_property & EventProperty.TIMESTAMP:
            self._time_delta = c_etl_headers.uint64(payload)

        if self.event_property & EventProperty.COMPONENT_ID:
            raise NotImplementedError("header.EventProperty & 4")

        if self.event_property & EventProperty.SYSTEMINFO and bytes_left(payload) >= 8:
            self._thread_id = c_etl_headers.uint32(payload)
            self._process_id = c_etl_headers.uint32(payload)

    @property
    def time_delta(self) -> int:
        return self._time_delta

    @property
    def version(self) -> int:
        return None

    @property
    def id(self) -> int:
        """The id of the message event."""
        return self.header.Id

    @property
    def event_property(self) -> int:
        """What type of payload to expect."""
        return self.header.EventProperty

    @property
    def provider_id(self) -> UUID:
        return self._provider_id

    @property
    def thread_id(self) -> int:
        return self._thread_id

    @property
    def process_id(self) -> int:
        return self._process_id

    @property
    def sequence_number(self) -> int:
        return self._sequence_number

    def _contains_provider_id(self, payload: BytesIO) -> bool:
        if not (bytes_left(payload) >= 16):
            return False
        else:
            event_property = self.event_property & (EventProperty.GUID | EventProperty.COMPONENT_ID)
            return event_property == EventProperty.GUID

    def additional_header_fields(self) -> Dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
        }


class EventTraceHeader(Header):
    @property
    def minimal_size(self) -> int:
        return 0x30

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.EventTraceHeader

    @property
    def thread_id(self) -> int:
        """The thread id that created this event."""
        return self.header.ThreadId

    @property
    def process_id(self) -> int:
        """The process id that created this event."""
        return self.header.ProcessId

    def additional_header_fields(self) -> Dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
        }


class EventInstanceHeader(Header):
    @property
    def minimal_size(self) -> int:
        return 0x38

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.EventInstanceHeader

    def additional_header_fields(self) -> Dict[str, Any]:
        return {
            "ThreadId": self.header.ids.information.ThreadId,
            "ProcessId": self.header.ids.information.ProcessId,
        }


class EventInstanceGUIDHeader(Header):
    """A more expanded EventInstanceHeader.

    This is created from an EventInstanceHeader, but it's not quite clear which one is specifically used.
    For now, this header is default."""

    @property
    def minimal_size(self) -> int:
        return 0x48

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.EventInstanceGUIDHeader

    @property
    def thread_id(self):
        """The thread id that created this event."""
        return self.header.ThreadId

    @property
    def process_id(self):
        """The process id that created this event."""
        return self.header.ProcessId

    @property
    def parent_guid(self):
        return UUID(bytes_le=self.header.ParentGuid)

    def additional_header_fields(self) -> Dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
            "ParentGuid": f"{self.parent_guid}",
        }


class ErrorHeader(Header):
    """When an error event was created. However, the structure of the header isn't clear."""

    @property
    def minimal_size(self) -> int:
        return 0x50

    @property
    def _header_type(self) -> Structure:
        return None

    def additional_header_fields(self) -> Dict[str, Any]:
        return {}
