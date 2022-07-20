# Sources for the logfile header:
#  - https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header
#  - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/trace_logfile_header.htm
from enum import IntEnum

from dissect.cstruct import Structure, cstruct

from dissect.etl.exceptions import InvalidHookIdException
from dissect.etl.headers.system import SystemHeader

logfile_def = """
struct SYSTEMTIME {
    WORD    wYear;
    WORD    wMonth;
    WORD    wDayOfWeek;
    WORD    wDay;
    WORD    wHour;
    WORD    wMinute;
    WORD    wSecond;
    WORD    wMilliseconds;
};

struct TZInfo {
    LONG        Bias;
    wchar       StandardName[32];
    SYSTEMTIME  StandardDate;
    LONG        StandardBias;
    wchar       DaylightName[32];
    SYSTEMTIME  DaylightDate;
    LONG        DaylightBias;
};

struct TraceLogfileHeader {
    uint32  BufferSize;
    union   version_information {
        uint32 Version;
        struct VersionDetail {
            uchar MajorVersion;
            uchar MinorVersion;
            uchar SubVersion;
            uchar SubMinorVersion;
        };
    };
    uint32  ProviderVersion;
    uint32  NumberOfProcessors;
    uint64  EndTime;
    uint32  TimerResolution;
    uint32  MaximumFileSize;
    uint32  LogFileMode;
    uint32  BuffersWritten;
    union {
        char LogInstanceGuid[16];
        struct {
            uint32  StartBuffers;
            uint32  PointerSize;
            uint32  EventsLost;
            uint32  CpuSpeedInMHz;
        };
    };
    PWSTR   LoggerName;
    PWSTR   LogFileName;
    TZInfo  TimeZone;
    uint32  padding; /* The timezone info is said to be 0xB0 bytes... no clue why */
    uint64  BootTime;
    uint64  PerfFreq;
    uint64  StartTime;
    uint32  ReservedFlags;
    uint32  BufferLost;
};

struct LogFileNames {
    wchar LoggerName[];
    wchar LogFileName[];
};
"""


class ReservedFlags(IntEnum):
    PERFORMANCE_FREQ = 1
    FILETIME = 2
    CPU_FREQ = 3


class LogfileHeader:
    """The logfile header.

    It is the payload of the first event in an ETL file.

    There is also a manifest file that parses this specific header.
    However, as it is a standard event that is inside every ETL file
    (and it requires some special handling for timestamp calculation) there is a dedicated parser for it.
    """

    def __init__(self, calling_header: SystemHeader):
        if calling_header.hook_id != 0x0000:
            raise InvalidHookIdException("Called with invalid hook ID")
        self._header = None
        self.system_header = calling_header
        self.data = calling_header.payload

        # Load the logfile definition depending on the pointer type used.
        self.c_logfile = cstruct()
        self.c_logfile.load(self._create_string_pointer_type() + logfile_def)

        # At the end of the logfileheader it defines the LoggerName and the LogFileName
        # The pointers with the same name in the header do not seem to relate to these strings
        # In old versions of windows, pre 6.1, they were used to point to the strings
        # in >= 6.1 they take enumarated values of HAL_PLATFORM_TIMER_SOURCE which define some time source information.

        # The strings are defined as nullterminated strings so we read them with a cstruct from the payload.
        logfile_names = self.c_logfile.LogFileNames(self.payload)
        self.logger_name = logfile_names.LoggerName
        self.log_filename = logfile_names.LogFileName
        self.timestamp_scale = self._calculate_timestamp_scale()
        self.timestamp_base = self._calculate_timestamp_base()

    @property
    def header(self) -> Structure:
        """The parsed header of the event."""
        if not self._header:
            self._header = self.c_logfile.TraceLogfileHeader(self.data[: self.minimal_size])
        return self._header

    @property
    def payload(self) -> memoryview:
        """The payload data for the event."""
        return self.data[self.minimal_size :]

    def _create_string_pointer_type(self) -> str:
        """Return the string pointer type."""
        return f"typedef {self._get_pwstr_type()} PWSTR;"

    def _get_pwstr_type(self) -> str:
        return "uint64" if self.is_64bit else "uint32"

    @property
    def is_64bit(self) -> bool:
        # If the event header is 64-bit, so is the logheader
        return self.system_header.is_64bit

    @property
    def minimal_size(self) -> int:
        """Minimum header size."""
        return 0x118 if self.is_64bit else 0x110

    def _calculate_timestamp_scale(self) -> float:
        """Calculate the timestamp_scale variable."""
        clock_mode_dict = {
            ReservedFlags.PERFORMANCE_FREQ: 10000000 / self.perf_freq,
            ReservedFlags.FILETIME: 1.0,
            ReservedFlags.CPU_FREQ: 10.0 / self.cpu_speed_in_MHz,
        }
        return clock_mode_dict.get(self.header.ReservedFlags, 0)

    def _calculate_timestamp_base(self) -> int:
        """Calculate the timestamp_base variable.

        This is based on the start_time in the header and the delta of the system_header
        """
        return self.start_time - int(self.timestamp_scale * self.system_header.time_delta)

    @property
    def cpu_speed_in_MHz(self) -> int:
        """The CPU speed that was recorded inside the logfile header."""
        return self.header.CpuSpeedInMHz

    @property
    def perf_freq(self) -> int:
        """The performance frequency used to record the etl file."""
        return self.header.PerfFreq

    @property
    def start_time(self) -> int:
        """When the etl file started to record."""
        return self.header.StartTime

    @property
    def pointer_size(self) -> int:
        """The size of stringpointers."""
        return self.header.PointerSize

    @property
    def end_time(self) -> int:
        """The time the last event was written to the ETL file."""
        return self.header.EndTime

    @property
    def buffers_written(self) -> int:
        """The number of buffers written to the file."""
        return self.header.BuffersWritten
