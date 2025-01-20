from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.etl.exceptions import InvalidHookIdException
from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.headers.utils import select_event_header

from .testutils import buffer_system_data

if TYPE_CHECKING:
    from dissect.etl.headers.headers import Header


def create_header(marker: int) -> Header:
    marker_bytes = int.to_bytes(marker, 4, "little")
    event_data = marker_bytes + b"\xad\xde" + buffer_system_data()[6:].tobytes()
    data = memoryview(event_data)
    return select_event_header(data, Mock())


def create_event(bit64: bool) -> Header:
    return create_header(0xC0020000 if bit64 else 0xC0010000)


def test_logfile_header_creation() -> None:
    assert LogfileHeader(create_event(bit64=False))


def test_logfile_wrong_hookid() -> None:
    mocked_system_header = Mock()
    mocked_system_header.hook_id = 0x1
    with pytest.raises(InvalidHookIdException):
        LogfileHeader(mocked_system_header)


@pytest.mark.parametrize(
    ("is_64_bit", "expected_size"),
    [
        (True, 0x118),
        (False, 0x110),
    ],
)
def test_logfile_header_size(is_64_bit: bool, expected_size: int) -> None:
    header = LogfileHeader(create_event(bit64=is_64_bit))
    assert header.minimal_size == expected_size
    assert len(header.header) == expected_size


def test_logfile_payload() -> None:
    header = LogfileHeader(create_event(bit64=True))
    assert header.logger_name == "PerfDiag Logger"
    assert header.log_filename == r"C:\Windows\system32\WDI\LogFiles\BootPerfDiagLogger.etl"


def test_pointer_size() -> None:
    header = LogfileHeader(create_event(bit64=True))
    assert header.pointer_size == 8


def test_cpumhz() -> None:
    header = LogfileHeader(create_event(bit64=True))
    assert header.cpu_speed_in_MHz == 0x840


@patch.object(LogfileHeader, "header", ReservedFlags=2)
def test_timscale_2(mocked_header: LogfileHeader) -> None:
    header = LogfileHeader(create_event(bit64=True))
    assert header.timestamp_scale == 1.0


@pytest.mark.parametrize(
    ("perf_freq", "expected_result"),
    [
        (10, 1000000.0),
        (20, 500000.0),
        (40, 250000.0),
        (0xDEADBEEF, 0.0026767107138356817),
    ],
)
@patch.object(LogfileHeader, "header", ReservedFlags=1)
def test_timescale_1(mocked_header: LogfileHeader, perf_freq: int, expected_result: float) -> None:
    mocked_header.PerfFreq = perf_freq
    header = LogfileHeader(create_event(bit64=True))
    assert header.timestamp_scale == expected_result


@pytest.mark.parametrize(
    ("perf_freq", "expected_result"),
    [
        (10, 1.0),
        (20, 0.5),
        (40, 0.25),
        (0xDEADBEEF, 2.6767107138356816e-09),
    ],
)
@patch.object(LogfileHeader, "header", ReservedFlags=3)
def test_timescale_3(mocked_header: LogfileHeader, perf_freq: int, expected_result: float) -> None:
    mocked_header.CpuSpeedInMHz = perf_freq
    header = LogfileHeader(create_event(bit64=True))
    assert header.timestamp_scale == expected_result


def test_starttime() -> None:
    logfile_info = LogfileHeader(create_event(bit64=True))
    assert logfile_info.start_time == 0x01D70AB5FE85A7C6


def test_timestamp_base() -> None:
    system_header = create_event(bit64=True)
    logfile_info = LogfileHeader(system_header)
    assert logfile_info.timestamp_base == 132586490803526455
