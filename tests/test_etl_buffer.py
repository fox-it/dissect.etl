from unittest.mock import MagicMock, patch

import pytest

from dissect import cstruct

from .test_wmi_buffer_header import RAW_BUFFER_HEADER as RAW_BUFFER_HEADER

import dissect.etl.etl as etl
from dissect.etl.etl import Buffer
from dissect.etl.exceptions import InvalidBufferError
from dissect.etl.utils import c_etl_definitions


def load_etl_definition():
    c_etl = cstruct.cstruct()
    c_etl.load(c_etl_definitions)
    return c_etl


def setup_mocked_etlfile(start_offset=0):
    mocked_etlfile = MagicMock()
    mocked_etlfile.fh.read.return_value = RAW_BUFFER_HEADER
    mocked_etlfile.fh.len.return_value = len(RAW_BUFFER_HEADER)
    mocked_etlfile.fh.tell.return_value = start_offset + 0x48
    return mocked_etlfile


def setup_buffer_with_offsets(header_offset, data_offset, start_offset=0):
    mocked_etl = setup_mocked_etlfile()
    mocked_etl.fh.tell.return_value = header_offset
    etl.c_etl = MagicMock()
    etl.c_etl.BufferHeader.return_value.Offset = data_offset
    return Buffer(mocked_etl, start_offset)


def setup_buffer_iterator(mocked_read_record, header_offset, data_offset):
    mocked_read_record.next_offset = 10
    buffer = setup_buffer_with_offsets(header_offset=header_offset, data_offset=data_offset)
    buffer_iterator = iter(buffer)
    return buffer_iterator


def test_buffer_data_len():
    mocked_etl = setup_mocked_etlfile()
    mocked_etl.c_etl = load_etl_definition()

    buffer = Buffer(mocked_etl, 0)

    mocked_etl.fh.read.assert_called_with(buffer.data_size - buffer.data_offset)


@patch.object(Buffer, "read_record")
def test_buffer_iteration_succeed(mocked_read_record):
    buffer_iterator = setup_buffer_iterator(mocked_read_record, header_offset=0, data_offset=15)
    assert next(buffer_iterator) == mocked_read_record.return_value


@pytest.mark.parametrize("header_offset,data_offset", [(0, 10), (0, 0)])
@patch.object(Buffer, "read_record", side_effect=[EOFError])
def test_buffer_iterations(mocked_read_record, header_offset, data_offset):
    buffer_iterator = setup_buffer_iterator(mocked_read_record, header_offset, data_offset)
    with pytest.raises(StopIteration):
        next(buffer_iterator)


def test_negative_read_offset():
    with pytest.raises(InvalidBufferError):
        setup_buffer_with_offsets(header_offset=10, data_offset=5)
