from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from dissect.cstruct import cstruct

import dissect.etl.etl as etl
from dissect.etl.c_etl import etl_def
from dissect.etl.etl import Buffer
from dissect.etl.exceptions import InvalidBufferError

from .test_wmi_buffer_header import RAW_BUFFER_HEADER

if TYPE_CHECKING:
    from collections.abc import Iterator


def load_etl_definition() -> cstruct:
    return cstruct().load(etl_def)


def setup_mocked_etlfile(start_offset: int = 0) -> MagicMock:
    mocked_etlfile = MagicMock()
    mocked_etlfile.fh.read.return_value = RAW_BUFFER_HEADER
    mocked_etlfile.fh.len.return_value = len(RAW_BUFFER_HEADER)
    mocked_etlfile.fh.tell.return_value = start_offset + 0x48
    return mocked_etlfile


def setup_buffer_with_offsets(data_offset: int, start_offset: int = 0) -> Buffer:
    mocked_etl = setup_mocked_etlfile()
    etl.c_etl = MagicMock()
    etl.c_etl.BufferHeader.return_value.FilledBytes = data_offset
    etl.c_etl.BufferHeader.return_value.BufferSize = data_offset
    etl.c_etl.BufferHeader.__len__.return_value = 0x48
    return Buffer(mocked_etl, start_offset)


def setup_buffer_iterator(mocked_read_record: MagicMock, data_offset: int) -> Iterator[Buffer]:
    mocked_read_record.next_offset = 10
    buffer = setup_buffer_with_offsets(data_offset=data_offset)
    return iter(buffer)


def test_buffer_data_len() -> None:
    mocked_etl = setup_mocked_etlfile()
    mocked_etl.c_etl = load_etl_definition()

    buffer = Buffer(mocked_etl, 0)
    assert buffer.data

    mocked_etl.fh.read.assert_called_with(buffer.filled_bytes - buffer.data_offset)


@patch.object(Buffer, "read_record")
def test_buffer_iteration_succeed(mocked_read_record: Buffer) -> None:
    buffer_iterator = setup_buffer_iterator(mocked_read_record, data_offset=15)
    assert next(buffer_iterator) == mocked_read_record.return_value


@pytest.mark.parametrize(
    ("header_offset", "data_offset"),
    [(0, 10), (0, 0)],
)
@patch.object(Buffer, "read_record", side_effect=[EOFError])
def test_buffer_iterations(mocked_read_record: Buffer, header_offset: int, data_offset: int) -> None:
    buffer_iterator = setup_buffer_iterator(mocked_read_record, data_offset)
    with pytest.raises(StopIteration):
        next(buffer_iterator)


def test_negative_read_offset() -> None:
    buffer = setup_buffer_with_offsets(start_offset=10, data_offset=5)
    with pytest.raises(InvalidBufferError):
        assert buffer.data


def test_different_buffer_sizes() -> None:
    buffer1 = Buffer(MagicMock(), 0)
    buffer1._header = MagicMock()
