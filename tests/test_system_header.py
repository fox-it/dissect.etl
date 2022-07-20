from unittest.mock import Mock

import pytest

from dissect.etl.exceptions import InvalidMarkerError
from dissect.etl.headers.utils import select_event_header

SYSTEM_EVENT = (
    b"\x02\x00\x02\xC0\x44\x00\x05\x00\xB4\x00\x00\x00\x04\x00\x00\x00"
    b"\x8F\x8C\x29\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
    b"\x07\x03\x00\x00\x04\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x50\x00\x00\x00\x00\x00\x00\x00"
)


def create_event(EVENT: bytearray):
    header_data = memoryview(EVENT)
    return select_event_header(header_data, Mock())


# Parse the system header as I imagined it should
def test_system_header():
    event = create_event(SYSTEM_EVENT)
    header = event.header
    assert header.Version == 0x0002
    assert header.Marker == 0xC002
    assert header.Size == 0x44
    assert header.OpCode == 0x5
    assert header.Group == 0x0
    assert header.ThreadId == 0xB4
    assert header.ProcessId == 0x4
    assert header.TimeDelta == 0x298C8F
    assert header.ProcessorTime == 0x1


def test_parse_failed():
    with pytest.raises(InvalidMarkerError):
        create_event(SYSTEM_EVENT[1:])
