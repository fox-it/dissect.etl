from abc import abstractmethod
from typing import Any, Dict
from uuid import UUID

from dissect.cstruct.types.structure import Structure

from dissect.etl.headers.headers import Header
from dissect.etl.utils import c_etl_headers, lookup_guid


class SystemSpecificHeader(Header):
    @property
    @abstractmethod
    def _minimal_size(self) -> int:
        """Minimum size for this event."""
        pass

    @property
    def size(self) -> int:
        return c_etl_headers.uint16(self.data[4:6])

    @property
    def minimal_size(self) -> int:
        """Minimum header size.

        Adds additional header bytes to the result to create a correct
        payload offset.
        """
        return self._minimal_size + self._additional_header_bytes()

    @property
    def hook_id(self) -> int:
        """An ID that identifies who created the event."""
        return (self.group << 8) | self.opcode

    @property
    def opcode(self) -> int:
        """A code used to select the type of event inside the header."""
        return self.header.OpCode

    @property
    def group(self) -> int:
        """A code used to select the provider for this header."""
        return self.header.Group

    @property
    def provider_id(self) -> UUID:
        return lookup_guid(self.header.Group, self.header.OpCode)

    def _additional_header_bytes(self) -> int:
        extra = 0
        if self.marker & 0x8000:
            extra = 8
        if self.marker & 0x0700:
            extra += 8 * ((self.marker & 0x0700) >> 8)
        return extra


class SystemHeader(SystemSpecificHeader):
    """
    Creates a System header.
    This header has the following types associated with them.
        Version
        Marker
        Size
        OpCode
        Group
        ThreadId
        ProcessId
        TimeDelta
        ProcessorTime

    """

    @property
    def _minimal_size(self) -> int:
        return 0x20

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.SystemHeader

    @property
    def process_id(self) -> int:
        """The process id that created this event."""
        return self.header.ProcessId

    @property
    def processor_time(self) -> int:
        """The time it took on the processor."""
        return self.header.ProcessorTime

    @property
    def thread_id(self) -> int:
        """The thread id that created this event."""
        return self.header.ThreadId

    def additional_header_fields(self) -> Dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
            "ProcessorTime": self.processor_time,
        }


class CompactSystemHeader(SystemSpecificHeader):
    """
    Creates a compact system header.
    This header has the following types associated with them.
        Version
        Marker
        Size
        OpCode
        Group
        ThreadId
        ProcessId
        TimeDelta

    """

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.CompactSystemHeader

    @property
    def _minimal_size(self) -> int:
        return 0x18

    @property
    def process_id(self) -> int:
        """The process id that created this event."""
        return self.header.ProcessId

    @property
    def thread_id(self) -> int:
        """The thread id that created this event."""
        return self.header.ThreadId

    def additional_header_fields(self) -> Dict[str, Any]:
        return {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
        }


class PerfinfoTraceHeader(SystemSpecificHeader):
    """A header that records performance events for windows."""

    @property
    def _minimal_size(self) -> int:
        return 0x10

    @property
    def _header_type(self) -> Structure:
        return c_etl_headers.PerformanceInfoHeader

    def additional_header_fields(self) -> Dict[str, Any]:
        return {}
