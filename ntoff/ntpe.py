"""Minimal PE reader for the one thing we need from a kernel image: its build key.

The design (5.2) keys every build on the PDB GUID + Age recorded by the linker,
not on the build number. This module extracts that key the same way the runtime
resolver does in kernel mode (9.2): walk the debug directory, find the CodeView
entry, read CV_INFO_PDB70. Keeping the two implementations structurally
identical is deliberate -- a mismatch here means the blob a driver ships can
never match the kernel it runs on.

Everything is expressed against a random-access `read(offset, size)` so the
same code serves a local file and a remote image. That matters more than it
looks: Winbindex does not publish PDB GUIDs, so every build we index needs its
binary read (4.4), and a kernel is 8 to 14 MB. Reading only the few hundred
bytes that actually carry the key turns the backfill from tens of gigabytes
into tens of megabytes, which is the difference between a polite crawl and one
that gets us blocked.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DEBUG_TYPE_CODEVIEW = 2
CV_SIGNATURE_RSDS = 0x53445352  # 'RSDS'

_SIZEOF_DEBUG_DIRECTORY = 28
_SIZEOF_SECTION_HEADER = 40
_SIZEOF_CV_INFO_PDB70 = 24  # signature + guid + age, before the name

Reader = Callable[[int, int], bytes]


class ShortRead(ValueError):
    """The image ended before a structure we were told to expect."""


@dataclass(frozen=True)
class PdbKey:
    """The msdl lookup key, and the same key the runtime blob is indexed by."""

    guid: uuid.UUID
    age: int
    pdb_name: str

    @property
    def key(self) -> str:
        """`<GUID 32 hex, no dashes><Age hex>` -- the msdl path component."""
        return f"{self.guid.hex.upper()}{self.age:X}"

    @property
    def guid_bytes(self) -> bytes:
        """Raw 16-byte memory representation.

        The blob's build table sorts on exactly these bytes (M1). The standard
        GUID string renders Data1/Data2/Data3 big-endian, so sorting on the
        string produces a different order than the runtime's memcmp and the
        binary search fails silently.
        """
        return self.guid.bytes_le

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.guid}-{self.age} ({self.pdb_name})"


@dataclass(frozen=True)
class PeInfo:
    machine: int
    timestamp: int
    size_of_image: int
    pdb_keys: tuple[PdbKey, ...]
    bytes_read: int = 0

    @property
    def machine_name(self) -> str:
        return {0x8664: "amd64", 0xAA64: "arm64", 0x014C: "x86"}.get(
            self.machine, f"0x{self.machine:04X}"
        )

    @property
    def pdb_key(self) -> PdbKey:
        if not self.pdb_keys:
            raise PeFormatError("image has no CodeView debug record")
        return self.pdb_keys[0]


class PeFormatError(ValueError):
    pass


class _Counting:
    """Wraps a reader so the caller can report how much of the image it touched.

    The number is the whole point of the ranged path, so it is measured rather
    than assumed.
    """

    def __init__(self, reader: Reader) -> None:
        self._reader = reader
        self.total = 0

    def __call__(self, offset: int, size: int) -> bytes:
        data = self._reader(offset, size)
        if len(data) < size:
            raise ShortRead(f"wanted {size} bytes at {offset:#x}, got {len(data)}")
        self.total += len(data)
        return data


def bytes_reader(data: bytes) -> Reader:
    def read(offset: int, size: int) -> bytes:
        return data[offset : offset + size]

    return read


def file_reader(path: str | Path) -> Reader:
    handle = open(path, "rb")

    def read(offset: int, size: int) -> bytes:
        handle.seek(offset)
        return handle.read(size)

    return read


def read_pe_info(source: str | Path | Reader) -> PeInfo:
    """Extract machine, timestamp, image size and every CodeView key."""
    reader = source if callable(source) else file_reader(source)
    read = _Counting(reader)

    header = read(0, 0x40)
    if struct.unpack_from("<H", header, 0)[0] != IMAGE_DOS_SIGNATURE:
        raise PeFormatError("not a DOS image")
    e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]

    # File header plus the largest optional header we care about, in one read.
    nt = read(e_lfanew, 24 + 240)
    if struct.unpack_from("<I", nt, 0)[0] != IMAGE_NT_SIGNATURE:
        raise PeFormatError("not a PE image")

    machine, section_count = struct.unpack_from("<HH", nt, 4)
    timestamp = struct.unpack_from("<I", nt, 8)[0]
    optional_size = struct.unpack_from("<H", nt, 20)[0]

    magic = struct.unpack_from("<H", nt, 24)[0]
    is_pe32_plus = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    size_of_image = struct.unpack_from("<I", nt, 24 + 56)[0]
    directories = 24 + (112 if is_pe32_plus else 96)

    debug_rva, debug_size = struct.unpack_from(
        "<II", nt, directories + IMAGE_DIRECTORY_ENTRY_DEBUG * 8
    )

    section_base = e_lfanew + 24 + optional_size
    section_table = read(section_base, section_count * _SIZEOF_SECTION_HEADER)
    sections = []
    for index in range(section_count):
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", section_table, index * _SIZEOF_SECTION_HEADER + 8
        )
        sections.append((virtual_address, virtual_size, raw_size, raw_pointer))

    keys = _read_codeview(read, sections, debug_rva, debug_size)
    return PeInfo(machine, timestamp, size_of_image, keys, read.total)


def _rva_to_offset(sections: list[tuple[int, int, int, int]], rva: int) -> int:
    for virtual_address, virtual_size, raw_size, raw_pointer in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            return raw_pointer + (rva - virtual_address)
    raise PeFormatError(f"rva {rva:#x} is outside every section")


def _read_codeview(
    read: Reader,
    sections: list[tuple[int, int, int, int]],
    debug_rva: int,
    debug_size: int,
) -> tuple[PdbKey, ...]:
    if not debug_rva or debug_size < _SIZEOF_DEBUG_DIRECTORY:
        return ()

    directory = read(_rva_to_offset(sections, debug_rva), debug_size)
    keys: list[PdbKey] = []

    for index in range(debug_size // _SIZEOF_DEBUG_DIRECTORY):
        entry = index * _SIZEOF_DEBUG_DIRECTORY
        entry_type = struct.unpack_from("<I", directory, entry + 12)[0]
        raw_size = struct.unpack_from("<I", directory, entry + 16)[0]
        raw_pointer = struct.unpack_from("<I", directory, entry + 24)[0]

        if entry_type != IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        if raw_pointer == 0 or raw_size < _SIZEOF_CV_INFO_PDB70 + 1:
            continue

        record = read(raw_pointer, raw_size)
        if struct.unpack_from("<I", record, 0)[0] != CV_SIGNATURE_RSDS:
            continue

        guid = uuid.UUID(bytes_le=record[4:20])
        age = struct.unpack_from("<I", record, 20)[0]
        terminator = record.find(b"\0", _SIZEOF_CV_INFO_PDB70)
        name = record[_SIZEOF_CV_INFO_PDB70 : terminator if terminator >= 0 else len(record)]
        keys.append(PdbKey(guid, age, name.decode("ascii", "replace")))

    return tuple(keys)
