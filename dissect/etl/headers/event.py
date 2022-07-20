from enum import IntEnum
from typing import Any, Dict, List, OrderedDict
from uuid import UUID

from dissect.util.sid import read_sid

from dissect.etl.exceptions import ExtendedDataItemException
from dissect.etl.headers.headers import Header
from dissect.etl.utils import c_etl_headers


def read_uuid(data: bytes) -> UUID:
    uuid_data = c_etl_headers.char[16](data)
    return UUID(bytes_le=uuid_data)


def read_instance_info(data: bytes) -> OrderedDict[str, Any]:
    instance_info = c_etl_headers.EVENT_HEADER_EXT_TYPE_ITEM_INSTANCE(data)
    output_dict = instance_info._values
    parent_guid = read_uuid(output_dict.get("ParentGuid"))
    output_dict["ParentGuid"] = f"{parent_guid}"
    return output_dict


def read_stack_trace(data: bytes) -> OrderedDict[str, Any]:
    instance_info = c_etl_headers.EVENT_HEADER_EXT_TYPE_STACK_TRACE32(data)
    address_length = (len(data) - 8) // instance_info._sizes["Address"]
    instance_info._values["Address"] = c_etl_headers.uint32[address_length](data[8:])
    return instance_info._values


def read_stack_trace64(data: bytes) -> OrderedDict[str, Any]:
    instance_info = c_etl_headers.EVENT_HEADER_EXT_TYPE_STACK_TRACE64(data)
    address_length = (len(data) - 8) // instance_info._sizes["Address"]
    instance_info._values["Address"] = c_etl_headers.uint64[address_length](data[8:])
    return instance_info._values


def read_provider_traits(data: bytes) -> OrderedDict[str, Any]:
    provider_traits = c_etl_headers.EVENT_HEADER_EXT_TYPE_PROVIDER_TRAIT(data)
    output_dict = provider_traits._values
    trait_offset = sum(provider_traits._sizes.values())
    traits = []
    while trait_offset < provider_traits.TraitSize:
        trait = c_etl_headers.TRAIT(data[trait_offset:])
        traits.append(trait._values)
        trait_offset += trait.TraitSize
    output_dict.update({"Traits": traits})
    return output_dict


class EventDescriptor:
    """An representation of the Event data in a event header."""

    __slots__ = [
        "id",
        "version",
        "channel",
        "level",
        "opcode",
        "task",
        "keywords",
    ]

    def __init__(self, header):
        self.id = header.Id
        self.version = header.Version
        self.channel = header.Channel
        self.level = header.Level
        self.opcode = header.OpCode
        self.task = header.Task
        self.keywords = header.Keywords


class ExtType(IntEnum):
    RELATED_ACTIVITY_ID = 0x1
    SID = 0x2
    TS_ID = 0x3
    INSTANCE_INFO = 0x4
    STACK_TRACE32 = 0x5
    STACK_TRACE64 = 0x6
    PEBS_INDEX = 0x7
    PMC_COUNTERS = 0x8
    PSM_KEY = 0x9
    EVENT_KEY = 0xA
    EVENT_SCHEMA_TL = 0xB
    PROV_TRAITS = 0xC
    PROCESS_START_KEY = 0xD
    TYPE_MAX = 0xE
    UNKNOWN = 0x0


extended_data_item_reader = {
    ExtType.RELATED_ACTIVITY_ID: lambda x: {"Guid": f"{read_uuid(x)}"},
    ExtType.SID: lambda x: {"Sid": read_sid(x)},
    ExtType.TS_ID: lambda x: {"SessionId": c_etl_headers.uint32(x)},
    ExtType.INSTANCE_INFO: read_instance_info,
    ExtType.STACK_TRACE32: read_stack_trace,
    ExtType.STACK_TRACE64: read_stack_trace64,
    ExtType.PEBS_INDEX: lambda x: {"PebsIndex": c_etl_headers.uint32(x)},
    ExtType.PMC_COUNTERS: lambda x: {"PmcCounters": c_etl_headers.uint64[len(x) // 8](x)},
    ExtType.PSM_KEY: lambda x: {"PsmKey": c_etl_headers.uint64(x)},
    ExtType.EVENT_KEY: lambda x: {"EventKey": c_etl_headers.uint64(x)},
    ExtType.EVENT_SCHEMA_TL: lambda x: {"EventSchema": c_etl_headers.char[len(x)](x)},
    ExtType.PROV_TRAITS: read_provider_traits,
    ExtType.PROCESS_START_KEY: lambda x: {"ProcessStartKey": c_etl_headers.uint64(x)},
    ExtType.TYPE_MAX: lambda x: {"Max": c_etl_headers.char[len(x)](x)},
}


class EventHeaderExtendedDataItem:
    """Loads an extended data item from payload."""

    __slots__ = [
        "size",
        "reserved1",
        "ext_type",
        "linkage",
        "reserved2",
        "data_size",
        "data",
        "raw_data",
    ]

    def __init__(self, payload):
        header = c_etl_headers.EventHeaderExtendedDataItemHeader(payload)
        self.size = header.Size
        self.ext_type = self._extension_type(header.ExtType)
        self.reserved1 = header.Reserved1
        self.data_size = header.DataSize
        self.data = self._read_extension_type(self.ext_type, header.Data)
        self.raw_data = header.Data
        self.linkage = 0
        self.reserved2 = 0

        self.validate_header()

    def validate_header(self) -> None:
        if self.size < 8:
            raise ExtendedDataItemException("DataItem size smaller than 8 bytes.")

        if self.size % 8:
            raise ExtendedDataItemException("DataItem size not aligned with 8 bytes.")

        if self.data_size > self.size - 8:
            raise ExtendedDataItemException("Data size larger than DataItem size.")

    def _extension_type(self, item_type: int) -> ExtType:
        try:
            return ExtType(item_type)
        except ValueError:
            return ExtType.UNKNOWN

    def _read_extension_type(self, ext_type, data) -> dict:
        reader = extended_data_item_reader.get(ext_type)
        return reader(data) if reader else {}

    def __getattr__(self, name: str) -> Any:
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            pass
        return self.data.get(name)

    def __repr__(self):
        return (
            f"<EventHeaderExtendedDataItem Size={self.size} Reserved1={self.reserved1} ExtType={self.ext_type} "
            f"Linkage={self.linkage} Reserved2={self.reserved2} DataSize={self.data_size}>"
        )


class EventHeader(Header):
    @property
    def descriptor(self):
        """Event descriptor of the header."""
        return EventDescriptor(self.header)

    @property
    def header_extensions(self) -> List[EventHeaderExtendedDataItem]:
        """A list with all the extended data items for this Event."""
        return self._read_extensions()

    @property
    def minimal_size(self):
        """Minimum header size."""
        return 0x50

    @property
    def _header_type(self):
        """Type of header that will get parsed."""
        return c_etl_headers.EventHeader

    def _read_extensions(self) -> List[EventHeaderExtendedDataItem]:
        """Read header extensions from the payload"""
        count = 0
        items = []
        payload_pos = 0
        payload_size = len(self.payload)

        while True:
            if count >= 13:
                break

            if payload_pos + 8 > payload_size:
                break

            try:
                header_extension = EventHeaderExtendedDataItem(self.payload[payload_pos:])
            except (EOFError, ExtendedDataItemException):
                break

            items.append(header_extension)

            count += 1
            payload_pos += header_extension.size

        return items

    @property
    def provider_id(self):
        """Provider that generated this event."""
        return UUID(bytes=self.header.ProviderId)

    @property
    def activity_id(self):
        """The ID associated with the activity in the event.

        At least, that is my assumption."""
        return UUID(bytes_le=self.header.ActivityId)

    @property
    def opcode(self):
        """The opcode used in this event."""
        return self.header.OpCode

    @property
    def thread_id(self):
        """The thread id that created this event."""
        return self.header.ThreadId

    @property
    def process_id(self):
        """The process id that created this event."""
        return self.header.ProcessId

    def additional_header_fields(self) -> Dict[str, Any]:
        basic_information = {
            "ThreadId": self.thread_id,
            "ProcessId": self.process_id,
            "ActivityId": f"{self.activity_id}",
        }
        extensions = []
        for extension in self.header_extensions:
            extension_dict = {
                "ExtType": extension.ext_type,
            }
            extension_dict.update(extension.data)
            extensions.append(extension_dict)
        basic_information.update({"Extensions": extensions})
        return basic_information
