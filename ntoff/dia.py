"""DIA SDK extractor -- the oracle, not the product.

msdia140.dll is Microsoft's own PDB reader; if it and our parser disagree
about a bitfield, our parser is wrong. That is the entire reason this exists.
It cannot be the shipping extractor: it is Windows-only COM, and the pipeline
runs on Linux runners (3).

Activation is registration free. The DIA redistributable is normally
regsvr32'd, which needs admin; going through DllGetClassObject directly keeps
this runnable on a plain developer machine and on a CI runner that merely has
Visual Studio installed.
"""

from __future__ import annotations

import ctypes
import glob
from ctypes import POINTER, byref, c_int, c_void_p
from pathlib import Path

import comtypes
import comtypes.client
from comtypes import COMMETHOD, GUID, HRESULT, IUnknown

from .model import EnumConstant, EnumDef, Extraction, Member, TypeLayout

CLSID_DiaSource = GUID("{E6756135-1E65-4D17-8576-610761398C3C}")

SymTagData = 7
SymTagPublicSymbol = 10
SymTagUDT = 11
SymTagEnum = 12

LocIsStatic = 1
LocIsThisRel = 4
LocIsBitField = 6
LocIsConstant = 10

DataIsMember = 7

_DIA_SEARCH_GLOBS = (
    r"C:\Program Files\Microsoft Visual Studio\*\*\DIA SDK\bin\amd64\msdia140.dll",
    r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\DIA SDK\bin\amd64\msdia140.dll",
)


class IClassFactory(IUnknown):
    _iid_ = GUID("{00000001-0000-0000-C000-000000000046}")
    _methods_ = [
        COMMETHOD(
            [],
            HRESULT,
            "CreateInstance",
            (["in"], POINTER(IUnknown), "pUnkOuter"),
            (["in"], POINTER(GUID), "riid"),
            (["out"], POINTER(c_void_p), "ppv"),
        ),
        COMMETHOD([], HRESULT, "LockServer", (["in"], c_int, "fLock")),
    ]


def find_msdia() -> Path:
    for pattern in _DIA_SEARCH_GLOBS:
        matches = sorted(glob.glob(pattern))
        if matches:
            return Path(matches[-1])
    raise FileNotFoundError("msdia140.dll not found; install the Visual Studio DIA SDK")


def _create_data_source(dll: Path):
    dia = comtypes.client.GetModule(str(dll))
    library = ctypes.WinDLL(str(dll))
    library.DllGetClassObject.argtypes = [POINTER(GUID), POINTER(GUID), POINTER(c_void_p)]
    library.DllGetClassObject.restype = ctypes.HRESULT

    factory_ptr = c_void_p()
    library.DllGetClassObject(
        byref(CLSID_DiaSource), byref(IClassFactory._iid_), byref(factory_ptr)
    )
    factory = ctypes.cast(factory_ptr, POINTER(IClassFactory))
    source_ptr = factory.CreateInstance(None, byref(dia.IDiaDataSource._iid_))
    return dia, ctypes.cast(source_ptr, POINTER(dia.IDiaDataSource))


def _pick_definition(enumerator):
    """Choose the real record when a type name resolves to several symbols.

    A forward reference carries no members and a size of zero (6.3). Taking the
    first match would silently produce an empty type, which downstream looks
    identical to "this build removed the type".
    """
    best = None
    for index in range(enumerator.Count):
        candidate = enumerator.Item(index)
        if best is None or candidate.length > best.length:
            best = candidate
    return best


def _member_size(member) -> int:
    member_type = member.type
    if member_type is None:
        return 0
    return int(member_type.length)


# Names shared by many unrelated anonymous records. Both readers must agree on
# excluding them, or the comparison reports a disagreement about the *type set*
# as though it were a disagreement about a layout.
AMBIGUOUS_PLACEHOLDERS = frozenset(
    {"<unnamed-tag>", "<anonymous-tag>", "<unnamed-enum-tag>", "__unnamed"}
)


def _addressable(name: str) -> bool:
    return bool(name) and name not in AMBIGUOUS_PLACEHOLDERS         and not name.startswith("__unnamed_")


def _enum_names(scope) -> list[str]:
    enumerator = scope.findChildren(SymTagEnum, None, 0)
    names: set[str] = set()
    for index in range(enumerator.Count):
        symbol = enumerator.Item(index)
        if _addressable(symbol.name):
            names.add(symbol.name)
    return sorted(names)


def _udt_names(scope) -> list[str]:
    enumerator = scope.findChildren(SymTagUDT, None, 0)
    names: set[str] = set()
    for index in range(enumerator.Count):
        symbol = enumerator.Item(index)
        if symbol.length and _addressable(symbol.name):
            names.add(symbol.name)
    return sorted(names)


def extract(pdb_path: Path, type_names: list[str], symbol_names: list[str],
            pdb_key: str = "", enum_names: list[str] | None = None) -> Extraction:
    dll = find_msdia()
    _, source = _create_data_source(dll)
    source.loadDataFromPdb(str(pdb_path))
    session = source.openSession()
    scope = session.globalScope

    result = Extraction("dia", pdb_key)

    if type_names == ["*"]:
        type_names = _udt_names(scope)
    if enum_names == ["*"]:
        enum_names = _enum_names(scope)

    for enum_name in (enum_names or []):
        candidates = scope.findChildren(SymTagEnum, enum_name, 0)
        symbol = _pick_definition(candidates) if candidates.Count else None
        if symbol is None:
            result.missing_enums.append(enum_name)
            continue

        constants = []
        children = symbol.findChildren(SymTagData, None, 0)
        for index in range(children.Count):
            member = children.Item(index)
            if member.locationType != LocIsConstant:
                continue
            constants.append(EnumConstant(int(member.value), member.name))
        result.enums[enum_name] = EnumDef(enum_name, int(symbol.length), constants)

    for type_name in type_names:
        candidates = scope.findChildren(SymTagUDT, type_name, 0)
        symbol = _pick_definition(candidates) if candidates.Count else None
        if symbol is None or symbol.length == 0:
            result.missing_types.append(type_name)
            continue

        layout = TypeLayout(type_name, int(symbol.length))
        children = symbol.findChildren(SymTagData, None, 0)
        for index in range(children.Count):
            member = children.Item(index)
            if member.dataKind != DataIsMember:
                continue

            location = member.locationType
            if location == LocIsBitField:
                layout.members.append(
                    Member(
                        offset=int(member.offset),
                        name=member.name,
                        size=_member_size(member),
                        bit_position=int(member.bitPosition),
                        bit_count=int(member.length),
                    )
                )
            elif location == LocIsThisRel:
                layout.members.append(
                    Member(
                        offset=int(member.offset),
                        name=member.name,
                        size=_member_size(member),
                    )
                )
            # Static members carry no instance offset and are not part of the
            # layout; nothing else is expected inside a kernel struct.

        result.types[type_name] = layout

    if symbol_names == ["*"]:
        # DIA does not enumerate the public stream usefully from the global
        # scope, and the oracle's job is to check the parser's reading rather
        # than to be a second collector. Symbols are cross-checked by name
        # against whatever the subject produced; see `compare`.
        result.rvas = {}
    else:
        for symbol_name in symbol_names:
            rva = _find_rva(scope, symbol_name)
            if rva is None:
                result.missing_symbols.append(symbol_name)
            else:
                result.rvas[symbol_name] = rva

    return result


def resolve_symbols(pdb_path: Path, names: list[str]) -> dict[str, int]:
    """Look up specific symbol RVAs, for spot-checking a bulk extraction."""
    dll = find_msdia()
    _, source = _create_data_source(dll)
    source.loadDataFromPdb(str(pdb_path))
    scope = source.openSession().globalScope
    found: dict[str, int] = {}
    for name in names:
        rva = _find_rva(scope, name)
        if rva is not None:
            found[name] = rva
    return found


def _find_rva(scope, name: str) -> int | None:
    for tag in (SymTagData, SymTagPublicSymbol):
        enumerator = scope.findChildren(tag, name, 0)
        for index in range(enumerator.Count):
            symbol = enumerator.Item(index)
            if tag == SymTagData and symbol.locationType != LocIsStatic:
                continue
            rva = int(symbol.relativeVirtualAddress)
            if rva:
                return rva
    return None
