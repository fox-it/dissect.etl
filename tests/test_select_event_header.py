from unittest.mock import Mock

import pytest

from dissect.etl.exceptions import InvalidHeaderError
from dissect.etl.headers.utils import select_event_header


def create_header(marker: int, min_size: int = 0, other_bytes=b"\xAD\xDE"):

    marker_bytes = int.to_bytes(marker, 4, "little")
    amount_of_padding = min_size - len(marker_bytes) - len(other_bytes)
    padding_bytes = b"\x00" * amount_of_padding

    data = memoryview(marker_bytes + other_bytes + padding_bytes)
    header = select_event_header(data, Mock())

    try:
        additional_padding = b"\x00" * (len(header._header_type) - amount_of_padding)
    except TypeError:
        additional_padding = b""

    header.data = memoryview(marker_bytes + other_bytes + padding_bytes + additional_padding)
    return header


@pytest.mark.parametrize(
    "marker, expected_size",
    [
        (0xC0010000, 0x20),
        (0xC0020000, 0x20),
        (0xC0030000, 0x18),
        (0xC0040000, 0x18),
        (0xC00AADDE, 0x30),
        (0xC00BADDE, 0x48),
        (0xC00DADDE, 0x50),
        (0xC0100000, 0x10),
        (0xC0110000, 0x10),
        (0xC012ADDE, 0x50),
        (0xC013ADDE, 0x50),
        (0xC014ADDE, 0x30),
        (0xC015ADDE, 0x48),
    ],
)
def test_header_size(marker, expected_size):
    header = create_header(marker=marker, min_size=expected_size)
    assert header.minimal_size == expected_size


def test_message_headersize():
    header = create_header(marker=0x9000ADDE, other_bytes=b"\x00\x00\x00\x00")
    assert header.minimal_size == 0x8


def test_header_size_events():
    header = create_header(0xC00ADEAD)
    assert header.size == 0xDEAD


@pytest.mark.parametrize(
    "marker",
    [
        0xC0010000,
        0xC0020000,
        0xC0030000,
        0xC0040000,
        0xC0100000,
        0xC0110000,
    ],
)
def test_header_kernel_event_size(marker):
    header = create_header(marker)
    assert header.size == 0xDEAD


def test_invalid_header():
    with pytest.raises(InvalidHeaderError):
        create_header(0xC0FF0000)


def test_invalid_size():
    with pytest.raises(InvalidHeaderError):
        create_header(0xC00A0000)


@pytest.mark.parametrize(
    "marker",
    [
        0xC0020000,
        0xC0040000,
        0xC0110000,
        0xC013DEAD,
        0xC014DEAD,
        0xC015DEAD,
    ],
)
def test_is_64bit(marker):
    header = create_header(marker=marker, min_size=80)
    assert header.is_64bit


@pytest.mark.parametrize(
    "marker",
    [
        0xC0010000,
        0xC0030000,
        0xC0100000,
        0xC00ADEAD,
        0xC00BDEAD,
        0xC0100000,
        0xC012DEAD,
        0xC00DDEAD,
    ],
)
def test_is_32bit(marker):
    header = create_header(marker=marker, min_size=80)
    assert not header.is_64bit


@pytest.mark.parametrize(
    "marker, expected_size",
    [
        (0xC0018000, 8),
        (0xC0010700, 8 * 7),
        (0xC0018700, 8 * 8),
        (0xC0010600, 8 * 6),
        (0xC0010000, 0),
    ],
)
def test_additional_header_size(marker, expected_size):
    sys_header = create_header(marker)
    assert sys_header._additional_header_bytes() == expected_size
    assert sys_header.minimal_size == 0x20 + expected_size


@pytest.mark.parametrize(
    "marker, expected_fields",
    [
        (0xC0010000, {"ThreadId": 0, "ProcessId": 0, "ProcessorTime": 0}),
        (0xC0020000, {"ThreadId": 0, "ProcessId": 0, "ProcessorTime": 0}),
        (0xC0030000, {"ThreadId": 0, "ProcessId": 0}),
        (0xC0040000, {"ThreadId": 0, "ProcessId": 0}),
        (0xC00AADDE, {"ThreadId": 0, "ProcessId": 0}),
        (0xC00BADDE, {"ThreadId": 0, "ProcessId": 0, "ParentGuid": "00000000-0000-0000-0000-000000000000"}),
        (0xC00DADDE, {}),
        (0xC0100000, {}),
        (0xC0110000, {}),
        (
            0xC012ADDE,
            {"ThreadId": 0, "ProcessId": 0, "ActivityId": "00000000-0000-0000-0000-000000000000", "Extensions": []},
        ),
        (
            0xC013ADDE,
            {"ThreadId": 0, "ProcessId": 0, "ActivityId": "00000000-0000-0000-0000-000000000000", "Extensions": []},
        ),
        (0xC014ADDE, {"ThreadId": 0, "ProcessId": 0}),
        (0xC015ADDE, {"ThreadId": 0, "ProcessId": 0, "ParentGuid": "00000000-0000-0000-0000-000000000000"}),
    ],
)
def test_additional_fields(marker, expected_fields):
    header = create_header(marker)
    assert header.additional_header_fields() == expected_fields
