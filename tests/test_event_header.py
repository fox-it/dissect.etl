from unittest.mock import Mock

import pytest

from dissect.etl.exceptions import ExtendedDataItemException
from dissect.etl.headers.event import (
    EventHeader,
    EventHeaderExtendedDataItem,
    ExtType,
    read_provider_traits,
)
from dissect.etl.headers.headers import Marker
from dissect.etl.utils import c_etl_headers

EVENT_HEADER_EVENT = (
    b"\x12\x01\x13\xC0\x01\x00\x00\x00\xE8\x02\x00\x00\xE4\x02\x00\x00"
    b"\x2B\x15\x41\x0B\x00\x00\x00\x00\xA7\xCE\xDD\xB8\x20\xB5\x09\x49"
    b"\xBC\xEB\xE0\x17\x0C\x9F\x0E\x99\x00\x00\x00\x0B\x05\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x20\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x48\x00\x0C\x00\x01\x00\x3D\x00\x3D\x00\x4D\x69\x63\x72\x6F\x73"
    b"\x6F\x66\x74\x2E\x57\x69\x6E\x64\x6F\x77\x73\x2E\x53\x65\x72\x76"
    b"\x69\x63\x65\x43\x6F\x6E\x74\x72\x6F\x6C\x4D\x61\x6E\x61\x67\x65"
    b"\x72\x00\x13\x00\x01\x1A\x73\x50\x4F\xCF\x89\x82\x47\xB3\xE0\xDC"
    b"\xE8\xC9\x04\x76\xBA\x00\x00\x00\x38\x00\x0B\x00\x00\x00\x2C\x00"
    b"\x2C\x00\x00\x53\x65\x72\x76\x69\x63\x65\x48\x6F\x73\x74\x53\x74"
    b"\x61\x72\x74\x65\x64\x00\x53\x65\x72\x76\x69\x63\x65\x48\x6F\x73"
    b"\x74\x4E\x61\x6D\x65\x00\x01\x50\x49\x44\x00\x08\x00\x00\x00\x00"
    b"\x43\x00\x3A\x00\x5C\x00\x57\x00\x69\x00\x6E\x00\x64\x00\x6F\x00"
    b"\x77\x00\x73\x00\x5C\x00\x73\x00\x79\x00\x73\x00\x74\x00\x65\x00"
    b"\x6D\x00\x33\x00\x32\x00\x5C\x00\x73\x00\x70\x00\x70\x00\x73\x00"
    b"\x76\x00\x63\x00\x2E\x00\x65\x00\x78\x00\x65\x00\x00\x00\xF4\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
)


def create_header():
    header_data = memoryview(EVENT_HEADER_EVENT)
    marker = Marker(0xC000A0112)
    return EventHeader(marker, header_data, Mock())


def test_event_header():
    event = create_header()
    header = event.header

    assert header.Size == 0x112
    assert header.Marker == 0xC013
    assert header.Flags == 0x1
    assert header.EventProperty == 0x0
    assert header.ThreadId == 0x2E8
    assert header.ProcessId == 0x2E4
    assert header.TimeDelta == 0x0B41152B
    assert header.ProviderId == b"\xA7\xCE\xDD\xB8\x20\xB5\x09\x49\xBC\xEB\xE0\x17\x0C\x9F\x0E\x99"
    assert header.Id == 0x0000
    assert header.Version == 0x00
    assert header.Channel == 0x0B
    assert header.Level == 0x05
    assert header.OpCode == 0x0
    assert header.Task == 0x0
    assert header.Keywords == 0x200000000000
    assert header.ProcessorTime == 0x0200000011
    assert header.ActivityId == bytes([0x00] * 16)


def test_event_payload():
    event = create_header()
    assert len(event.payload) == 0x112 - event.minimal_size


@pytest.mark.parametrize(
    "size, data_size, exception_match",
    [
        (0, 0, r".*smaller than 8 bytes."),
        (9, 0, r".*not aligned with 8 bytes."),
        (16, 20, r".*larger than DataItem size."),
    ],
)
def test_event_small_dataitem(size, data_size, exception_match):
    event_data = create_extended_item_header(Size=size, DataSize=data_size)
    with pytest.raises(ExtendedDataItemException, match=exception_match):
        EventHeaderExtendedDataItem(event_data)


def create_extended_item_header(**kwargs):
    if "Data" in kwargs and "DataSize" not in kwargs:
        data_size = len(kwargs["Data"])
        data = kwargs["Data"]
        kwargs.pop("Data")
    elif "DataSize" in kwargs and "Data" not in kwargs:
        data_size = kwargs["DataSize"]
        data = b"\x00" * data_size
        kwargs.pop("DataSize")

    elif "DataSize" not in kwargs and "Data" not in kwargs:
        data_size = 8
        data = b"\x00" * data_size
    else:
        data_size = kwargs["DataSize"]
        data = kwargs["Data"]
        kwargs.pop("DataSize")
        kwargs.pop("Data")

    if "Size" in kwargs:
        size = kwargs["Size"]
        kwargs.pop("Size")
    else:
        size = data_size + 8
    return c_etl_headers.EventHeaderExtendedDataItemHeader(Size=size, DataSize=data_size, Data=data, **kwargs).dumps()


def test_event_header_extension():
    EventHeaderExtendedDataItem(memoryview(create_extended_item_header()))


@pytest.mark.parametrize(
    "item_type, expected_value",
    [
        (0x1, "RELATED_ACTIVITY_ID"),
        (0x2, "SID"),
        (0x3, "TS_ID"),
        (0x4, "INSTANCE_INFO"),
        (0x5, "STACK_TRACE32"),
        (0x6, "STACK_TRACE64"),
        (0x7, "PEBS_INDEX"),
        (0x8, "PMC_COUNTERS"),
        (0x9, "PSM_KEY"),
        (0xA, "EVENT_KEY"),
        (0xB, "EVENT_SCHEMA_TL"),
        (0xC, "PROV_TRAITS"),
        (0xD, "PROCESS_START_KEY"),
        (0xE, "TYPE_MAX"),
        (0x0, "UNKNOWN"),
        (0xF, "UNKNOWN"),
    ],
)
def test_extension_ext_type(item_type, expected_value):
    header = create_extended_item_header()

    data = EventHeaderExtendedDataItem(header)
    output = data._extension_type(item_type).name

    assert output == expected_value


@pytest.mark.parametrize(
    "item_type, expected_value",
    [
        (ExtType.RELATED_ACTIVITY_ID, {"Guid": "00000000-0000-0000-0000-000000000000"}),
        (ExtType.SID, {"Sid": "S-0-0"}),
        (ExtType.TS_ID, {"SessionId": 0}),
        (
            ExtType.INSTANCE_INFO,
            {"InstanceId": 0, "ParentInstanceId": 0, "ParentGuid": "00000000-0000-0000-0000-000000000000"},
        ),
        (ExtType.STACK_TRACE32, {"MatchId": 0, "Address": [0, 0, 0, 0]}),
        (ExtType.STACK_TRACE64, {"MatchId": 0, "Address": [0, 0]}),
        (ExtType.PEBS_INDEX, {"PebsIndex": 0}),
        (ExtType.PMC_COUNTERS, {"PmcCounters": [0, 0, 0]}),
        (ExtType.PSM_KEY, {"PsmKey": 0}),
        (ExtType.EVENT_KEY, {"EventKey": 0}),
        (ExtType.EVENT_SCHEMA_TL, {"EventSchema": b"\x00" * 24}),
        (ExtType.PROV_TRAITS, {"TraitSize": 0, "ProviderName": b"", "Traits": []}),
        (ExtType.PROCESS_START_KEY, {"ProcessStartKey": 0}),
        (ExtType.TYPE_MAX, {"Max": b"\x00" * 24}),
        (ExtType.UNKNOWN, {}),
    ],
)
def test_extension_output_data(item_type, expected_value):
    header = create_extended_item_header()
    data = EventHeaderExtendedDataItem(header)
    input_data = b"\x00" * 24
    assert data._read_extension_type(item_type, input_data) == expected_value


def test_extension_key_in_data():
    header = create_extended_item_header(ExtType=ExtType.RELATED_ACTIVITY_ID, Data=b"\x00" * 16)
    data = EventHeaderExtendedDataItem(header)
    assert data.Guid == "00000000-0000-0000-0000-000000000000"


def test_extension_key_not_in_data():
    header = create_extended_item_header(ExtType=ExtType.UNKNOWN, Data=b"\x00" * 16)
    data = EventHeaderExtendedDataItem(header)
    assert data.Guid is None


def test_extension_provider_trait():
    trait_data = (
        b"=\x00Microsoft.Windows.ServiceControlManager\x00\x13\x00\x01\x1asPO\xcf\x89\x82G\xb3\xe0\xdc\xe8\xc9\x04v\xba"
    )
    traits = read_provider_traits(trait_data)
    assert traits["TraitSize"] == 0x3D
    assert traits["ProviderName"] == b"Microsoft.Windows.ServiceControlManager"
    assert traits["Traits"][0]["TraitSize"] == 0x13
    assert traits["Traits"][0]["Type"] == 0x1
    assert traits["Traits"][0]["Data"] == b"\x1asPO\xcf\x89\x82G\xb3\xe0\xdc\xe8\xc9\x04v\xba"
