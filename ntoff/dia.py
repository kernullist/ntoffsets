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


SymTagFunctionType = 13
SymTagPointerType = 14
SymTagArrayType = 15
SymTagBaseType = 16
SymTagTypedef = 17

# DIA's BasicType enum. Only the ones a kernel struct can hold are listed; an
# unlisted one renders empty rather than guessing, and the gate then reports a
# disagreement, which is the correct outcome for a case nobody has looked at.
_BT_VOID, _BT_CHAR, _BT_WCHAR = 1, 2, 3
_BT_INT, _BT_UINT, _BT_FLOAT = 6, 7, 8
_BT_BOOL, _BT_LONG, _BT_ULONG = 10, 13, 14
_BT_COMPLEX, _BT_HRESULT = 28, 31
_BT_CHAR16, _BT_CHAR32, _BT_CHAR8 = 32, 33, 34

# Keyed by (basic type, byte width), because DIA reports width separately from
# kind. The spelling has to match `typename.rs` exactly: the whole point of the
# oracle is that a difference in the output is a difference in the reading, so
# a difference in vocabulary would read as a bug that is not there.
_BASIC_NAMES = {
    (_BT_VOID, 0): "void",
    (_BT_CHAR, 1): "char",
    (_BT_CHAR8, 1): "char",
    (_BT_WCHAR, 2): "wchar_t",
    (_BT_CHAR16, 2): "char16_t",
    (_BT_CHAR32, 4): "char32_t",
    (_BT_INT, 1): "char",
    (_BT_INT, 2): "short",
    (_BT_INT, 4): "int",
    (_BT_INT, 8): "__int64",
    (_BT_INT, 16): "__int128",
    (_BT_UINT, 1): "unsigned char",
    (_BT_UINT, 2): "unsigned short",
    (_BT_UINT, 4): "unsigned int",
    (_BT_UINT, 8): "unsigned __int64",
    (_BT_UINT, 16): "unsigned __int128",
    (_BT_LONG, 4): "long",
    (_BT_LONG, 8): "__int64",
    (_BT_ULONG, 4): "unsigned long",
    (_BT_ULONG, 8): "unsigned __int64",
    (_BT_FLOAT, 2): "half",
    (_BT_FLOAT, 4): "float",
    (_BT_FLOAT, 8): "double",
    (_BT_FLOAT, 16): "long double",
    (_BT_BOOL, 1): "bool",
    (_BT_BOOL, 2): "bool16",
    (_BT_BOOL, 4): "bool32",
    (_BT_BOOL, 8): "bool64",
    (_BT_COMPLEX, 8): "_Complex float",
    (_BT_COMPLEX, 16): "_Complex double",
    (_BT_HRESULT, 4): "HRESULT",
}


def _attr(symbol, name, default=None):
    """DIA raises rather than returning null for properties a symbol lacks."""
    try:
        return getattr(symbol, name)
    except Exception:
        return default


def _type_name(symbol, depth: int = 0) -> str:
    """Spell a DIA type symbol the way `typename.rs` spells the same record.

    Written independently of the Rust renderer and diffed against it, for the
    same reason every other field is (13-2). A field the oracle does not
    produce is a field the gate cannot check, and the last time this codebase
    had one of those a chimera walked through three gates unnoticed.
    """
    if symbol is None or depth > 12:
        return ""

    tag = int(_attr(symbol, "symTag", 0) or 0)
    prefix = ""
    if _attr(symbol, "constType", False):
        prefix += "const "
    if _attr(symbol, "volatileType", False):
        prefix += "volatile "

    if tag == SymTagBaseType:
        base = int(_attr(symbol, "baseType", 0) or 0)
        width = int(_attr(symbol, "length", 0) or 0)
        name = _BASIC_NAMES.get((base, width), "")
        return prefix + name if name else ""

    if tag in (SymTagUDT, SymTagEnum):
        name = _attr(symbol, "name") or ""
        return prefix + name if name else ""

    if tag == SymTagTypedef:
        # The Rust reader never sees a typedef -- CodeView resolves member
        # types past them -- so following it through is what keeps the two
        # readings comparable.
        return _type_name(_attr(symbol, "type"), depth + 1)

    if tag == SymTagPointerType:
        target = _attr(symbol, "type")
        rendered = _type_name(target, depth + 1)
        if not rendered:
            return ""
        # A qualifier on the pointer symbol qualifies the pointer, not what it
        # points at, so it goes after the star. `T * volatile` and
        # `volatile T *` are different types and DIA reports both by setting
        # the same flag on different symbols.
        suffix = prefix.replace("const ", " const").replace("volatile ", " volatile")
        if int(_attr(target, "symTag", 0) or 0) == SymTagFunctionType:
            return rendered.replace(" ()", " (*)()", 1) + suffix
        return f"{rendered} *{suffix}"

    if tag == SymTagArrayType:
        element = _attr(symbol, "type")
        rendered = _type_name(element, depth + 1)
        if not rendered:
            return ""
        # A trailing zero-length array is a real declaration, so "counted
        # zero" and "could not count" have to stay apart: only the second one
        # renders unsized.
        count = int(_attr(symbol, "count", 0) or 0)
        if not count:
            stride = int(_attr(element, "length", 0) or 0)
            if not stride:
                return f"{prefix}{rendered}[]"
            count = int(_attr(symbol, "length", 0) or 0) // stride
        return f"{prefix}{rendered}[{count}]"

    if tag == SymTagFunctionType:
        returns = _type_name(_attr(symbol, "type"), depth + 1)
        return f"{returns} ()" if returns else ""

    return ""


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
                        type=_type_name(member.type),
                    )
                )
            elif location == LocIsThisRel:
                layout.members.append(
                    Member(
                        offset=int(member.offset),
                        name=member.name,
                        size=_member_size(member),
                        type=_type_name(member.type),
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
