from unittest.mock import Mock

from dissect import cstruct
from dissect.etl.utils import c_etl_definitions

RAW_BUFFER_HEADER = (
    b"\x00\x00\x10\x00\xA8\x02\x00\x00\xA8\x02\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x03\x00\x00\x00"
    b"\xA8\x02\x00\x00\x21\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
)


def load_etl_definition():
    c_etl = cstruct.cstruct()
    c_etl.load(c_etl_definitions)
    return c_etl


def test_buffer_header_parsed_correctly():
    mocked_filehandle = Mock()
    mocked_filehandle.read.return_value = RAW_BUFFER_HEADER
    loaded_definition = load_etl_definition()

    header = loaded_definition.BufferHeader(mocked_filehandle)

    assert header.BufferSize == 0x100000
    assert header.SavedOffset == 0x2A8
    assert header.CurrentOffset == 0x2A8
    assert header.ReferenceCounter == 0
    assert header.TimeDelta == 0
    assert header.SequenceNumber == 0
    assert header.Defined_1 == 0
    assert header.ProcessorIndex == 0x0
    assert header.LoggerId == 0x12
    assert header.ETW_BUFFER_STATE == 0x3
    assert header.Offset == 0x2A8
    assert header.BufferFlag == 0x21
    assert header.BufferType == 0x4
    assert header.unk17 == 0
    assert header.unk18 == 0
    assert header.unk19 == 0
    assert header.unk20 == 0
