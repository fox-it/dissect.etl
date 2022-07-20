import pytest
from dissect.etl.exceptions import InvalidMarkerError
from dissect.etl.headers.headers import Marker


@pytest.mark.parametrize(
    "marker, expected_headertype",
    [
        (0xC0010000, 0x01),
        (0xC0020000, 0x02),
        (0xC0030000, 0x03),
        (0xC0040000, 0x04),
        (0xC0100000, 0x10),
        (0xC0110000, 0x11),
        (0xC00A0000, 0x0A),
        (0xC00B0000, 0x0B),
        (0xC0140000, 0x14),
        (0xC0150000, 0x15),
        (0xC00D0000, 0x0D),
        (0xC0120000, 0x12),
        (0xC0130000, 0x13),
        (0x90000000, 0x0F),
    ],
)
def test_marker_headertype(marker, expected_headertype):
    marker = Marker(marker)
    assert marker.header_type == expected_headertype


def test_marker_remainder():
    marker = Marker(0xC00ADEAD)
    assert marker.remainder == 0xDEAD


def test_marker_invalidstart():
    with pytest.raises(InvalidMarkerError):
        Marker(0xD0000000).header_type
