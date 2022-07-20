import importlib
import os
import types
from collections import defaultdict
from string import Formatter
from xml.etree import ElementTree

import pkg_resources

from dissect import cstruct
from dissect.etl.exceptions import ManifestNotFoundError

MODPATH = "dissect.etl.manifests"

STRUCT_FMT = """
struct {name} {{
{fields}
}};
"""

CLASS_FMT = """
from uuid import UUID
from collections import namedtuple

from dissect import cstruct
from dissect.cstruct import RawType
from dissect.cstruct import Structure

Structure._calc_offsets = lambda _: None
Keyword = namedtuple('Keyword', ['name', 'message', 'mask'])
Task = namedtuple('Task', ['name', 'message', 'value'])
Event = namedtuple('Event', ['symbol', 'value', 'version', 'opcode', 'level', 'task', 'keywords', 'template'])


class VariableType(RawType):
    def __init__(self, cstruct, type_, size):
        self._t = type_
        super().__init__(cstruct, 'VariableType', size)

    def as_64bit(self):
        raise NotImplementedError()

    def as_32bit(self):
        raise NotImplementedError()

    def _read(self, stream):
        return self._t._read(stream)

    def _read_array(self, stream, count):
        return self._t._read_array(stream, count)

    def _read_0(self, stream):
        return self._t._read_0(stream)

    def _write(self, stream, data):
        return self._t._write(stream, data)

    def _write_array(self, stream, data):
        return self._t._write_array(stream, data)

    def _write_0(self, stream, data):
        return self._t._write_0(stream, data)


class EtwPointer(VariableType):
    def __init__(self, cstruct):
        super().__init__(cstruct, cstruct.uint64, 8)

    def as_64bit(self):
        if self.size == 8:
            return
        self.size = 8
        self._t = self.cstruct.uint64

    def as_32bit(self):
        if self.size == 4:
            return
        self.size = 4
        self._t = self.cstruct.uint32


class UserSID_blob(VariableType):
    def __init__(self, cstruct):
        super().__init__(cstruct, cstruct.char[16], 16)

    def as_64bit(self):
        if self.size == 16:
            return
        self.size = 16
        self._t = self.cstruct.char[16]

    def as_32bit(self):
        if self.size == 8:
            return
        self.size = 8
        self._t = self.cstruct.char[8]


PROVIDER_NAME = {provider_name!r}
PROVIDER_GUID = UUID({provider_guid!r})
PROVIDER_SYMBOL = {provider_symbol!r}

c_parser = cstruct.cstruct()
c_parser.addtype("EtwPointer", EtwPointer(c_parser))
c_parser.addtype("UserSID_blob", UserSID_blob(c_parser))
c_parser.load(\"\"\"
struct SYSTEMTIME {{
    WORD    wYear;
    WORD    wMonth;
    WORD    wDayOfWeek;
    WORD    wDay;
    WORD    wHour;
    WORD    wMinute;
    WORD    wSecond;
    WORD    wMilliseconds;
}};

struct UserSID {{
    uint8 revision;
    uint8 subAuthorityCount;
    char authority[6];
    uint32 subAuthorities[subAuthorityCount];
}};

struct SID {{
    UserSID_blob    blob;
    UserSID         sid;
}};

{templates}
\"\"\")

STRINGS = {{
{strings}
}}

KEYWORDS = {{
{keywords}
}}

EVENTS = {{
{events}
}}
"""

FIELD_MAP = {
    "Boolean": "uint8 {name}",
    "GUID": "char {name}[16]",
    "IPAddrV4": "uint32 {name}",
    "IPAddrV6": "char {name}[16]",
    "Pointer": "EtwPointer {name}",
    "SInt8": "int8 {name}",
    "SInt16": "int16 {name}",
    "SInt32": "int32 {name}",
    "SInt64": "int64 {name}",
    "SizeT": "uint32 {name}",
    "Struct": "KAPUT",
    "String": "char {name}[]",
    "SYSTEMTIME": "SYSTEMTIME {name}",
    "SID": "SID {name}",
    "WString": "wchar {name}[]",
    "UnicodeString": "wchar {name}[]",
}

CACHE = {}

c_parser = cstruct.cstruct()


def lookup(guid):
    global CACHE

    try:
        return CACHE[guid]
    except KeyError:
        pass

    try:
        mod = importlib.import_module("{}.{{{}}}".format(MODPATH, guid))
        CACHE[guid] = mod
        return mod
    except ImportError:
        pass

    try:
        mod = compile_xml(guid, get_resource_string("manifests/xml/{{{}}}.xml".format(guid)))
        CACHE[guid] = mod
        return mod
    except IOError:
        pass

    raise ManifestNotFoundError(guid)


def compile_file(guid, path):
    with open(path, "r") as fh:
        return compile_xml(guid, fh.read())


def compile_xml(guid, s):
    generated = generate_from_xml(s)
    # print generated
    code = compile(generated, f"<manifest {guid}>", "exec")
    module = types.ModuleType(str(guid))
    exec(code, module.__dict__)
    return module


def generate_from_file(path):
    with open(path, "r") as fh:
        return generate_from_xml(fh.read())


def generate_from_xml(s):
    e = ElementTree.fromstring(s)
    formatter = Formatter()

    strings = []
    for string in e.iter("{http://schemas.microsoft.com/win/2004/08/events}string"):
        strings.append("    '{id}': '{value}',".format(**string.attrib))

    keywords = []
    for keyword in e.iter("{http://schemas.microsoft.com/win/2004/08/events}keyword"):
        attr = keyword.attrib
        attr["message"] = attr["message"].split(".")[1][:-1]
        keywords.append("    '{name}': Keyword('{name}', STRINGS['{message}'], {mask}),".format(**attr))

    templates = []
    for template in e.iter("{http://schemas.microsoft.com/win/2004/08/events}template"):
        sname = template.attrib["tid"]

        if sname.startswith("0x"):
            sname = sname.replace("0x", "NULLx")

        fields = []
        for field in template:
            fattr = field.attrib
            fname = fattr["name"]
            ftype = fattr["inType"].split(":")[1]

            if ftype.lower() in c_parser.typedefs:
                ctype = ftype.lower()
                line = "{} {{name}}".format(ctype)
            else:
                line = FIELD_MAP[ftype]

            if "max" in fattr:
                line = "{}[{}]".format(line, fattr["max"])

            fields.append(line.format(name=fname))

        templates.append(
            STRUCT_FMT.format(
                name=sname,
                fields="\n".join(["    {};".format(field) for field in fields]),
            )
        )

    events = []
    for event in e.iter("{http://schemas.microsoft.com/win/2004/08/events}event"):
        attr = defaultdict(lambda: None)
        attr.update(event.attrib)

        if not attr["template"]:
            continue

        if attr["template"].startswith("0x"):
            attr["template"] = attr["template"].replace("0x", "NULLx")

        events.append(
            formatter.vformat(
                "    ({value}, {version}): Event('{symbol}', {value}, {version}, {opcode!r}, "
                "{level!r}, {task!r}, {keyword!r}, c_parser.{template}),",
                (),
                attr,
            )
        )

    provider = next(e.iter("{http://schemas.microsoft.com/win/2004/08/events}provider"))

    return CLASS_FMT.format(
        provider_name=provider.attrib["name"],
        provider_guid=provider.attrib["guid"],
        provider_symbol=provider.attrib.get("symbol"),
        templates="\n".join(templates),
        strings="\n".join(strings),
        keywords="\n".join(keywords),
        events="\n".join(events),
    )


def get_resource_string(path):
    if __package__:
        return pkg_resources.resource_string(__package__, path)

    fpath = _get_resource_path(path)
    with open(fpath, "r") as fh:
        return fh.read()


def get_resource_stream(path):
    if __package__:
        return pkg_resources.resource_stream(__package__, path)

    fpath = _get_resource_path(path)
    return open(fpath, "rb")


def _get_resource_path(path):
    fpath = os.path.join(os.path.dirname(__file__), path)
    if not os.path.exists(fpath):
        raise IOError("Can't find resource {}".format(path))
    return fpath
