from unittest.mock import Mock, patch

import pytest
from .testutils import buffer_system_data

from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.headers.utils import select_event_header


def create_header(marker):
    marker_bytes = int.to_bytes(marker, 4, "little")
    event_data = marker_bytes + b"\xAD\xDE" + buffer_system_data()[6:].tobytes()
    data = memoryview(event_data)
    return select_event_header(data, Mock())


def create_event(bit64: bool):
    marker = 0xC0010000
    if bit64:
        marker = 0xC0020000
    return create_header(marker)


def test_logfile_header_creation():
    LogfileHeader(create_event(bit64=False))


def test_logfile_wrong_hookid():
    mocked_system_header = Mock()
    mocked_system_header.hook_id = 0x1
    with pytest.raises(Exception):
        LogfileHeader(mocked_system_header)


@pytest.mark.parametrize("is_64_bit,expected_size", [(True, 0x118), (False, 0x110)])
def test_logfile_header_size(is_64_bit, expected_size):
    header = LogfileHeader(create_event(bit64=is_64_bit))
    assert header.minimal_size == expected_size
    assert len(header.header) == expected_size


def test_logfile_payload():
    header = LogfileHeader(create_event(bit64=True))
    assert header.logger_name == "PerfDiag Logger"
    assert header.log_filename == r"C:\Windows\system32\WDI\LogFiles\BootPerfDiagLogger.etl"


def test_pointer_size():
    header = LogfileHeader(create_event(bit64=True))
    assert header.pointer_size == 8


def test_cpumhz():
    header = LogfileHeader(create_event(bit64=True))
    assert header.cpu_speed_in_MHz == 0x840


@patch.object(LogfileHeader, "header", ReservedFlags=2)
def test_timscale_2(mocked_header):
    header = LogfileHeader(create_event(bit64=True))
    assert header.timestamp_scale == 1.0


@pytest.mark.parametrize(
    "perf_freq,expected_result",
    [
        (10, 1000000.0),
        (20, 500000.0),
        (40, 250000.0),
        (0xDEADBEEF, 0.0026767107138356817),
    ],
)
@patch.object(LogfileHeader, "header", ReservedFlags=1)
def test_timescale_1(mocked_header, perf_freq, expected_result):
    mocked_header.PerfFreq = perf_freq
    header = LogfileHeader(create_event(bit64=True))
    assert header.timestamp_scale == expected_result


@pytest.mark.parametrize(
    "perf_freq,expected_result",
    [(10, 1.0), (20, 0.5), (40, 0.25), (0xDEADBEEF, 2.6767107138356816e-09)],
)
@patch.object(LogfileHeader, "header", ReservedFlags=3)
def test_timescale_3(mocked_header, perf_freq, expected_result):
    mocked_header.CpuSpeedInMHz = perf_freq
    header = LogfileHeader(create_event(bit64=True))
    assert header.timestamp_scale == expected_result


def test_starttime():
    logfile_info = LogfileHeader(create_event(bit64=True))
    assert logfile_info.start_time == 0x01D70AB5FE85A7C6


def test_timestamp_base():
    system_header = create_event(bit64=True)
    logfile_info = LogfileHeader(system_header)
    assert logfile_info.timestamp_base == 132586490803526455
