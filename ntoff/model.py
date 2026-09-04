"""The shared shape of an extracted layout.

Both extractors -- DIA and the Rust `pdb` crate -- emit this, which is the
whole point: two independent readings of the same PDB that can be diffed
mechanically. 13 calls for cross validation; hand-copying WinDbg output does
not scale past a handful of types.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Bumped whenever the canonical serialization below changes. It lives in the
# storage path (`layouts/v1/<hash>.json`) rather than inside the hashed bytes,
# so that two generations of the same layout cannot collide in one namespace
# while still being told apart (M7).
LAYOUT_SCHEMA_VERSION = 1


@dataclass(frozen=True, order=True)
class Member:
    offset: int
    name: str
    size: int
    bit_position: int = 0
    bit_count: int = 0
    # Set only by the Rust extractor; see its model.rs for why DIA cannot
    # supply it. Excluded from `canonical_layout`, so it never moves a hash.
    union_group: int = 0

    @property
    def is_bitfield(self) -> bool:
        return self.bit_count != 0


@dataclass
class TypeLayout:
    name: str
    size: int
    members: list[Member] = field(default_factory=list)


@dataclass(frozen=True, order=True)
class EnumConstant:
    value: int
    name: str


@dataclass
class EnumDef:
    """An enumeration and its constants.

    Offsets say where a field is; enums say what the value there means. A
    caller reading `_EPROCESS.Protection` needs `PS_PROTECTED_TYPE` to do
    anything with the byte, and hard-coding the constant is the same per-build
    guesswork the offsets exist to remove.

    They live in the layout, not the build entry: enum values change far less
    often than they stay the same, so they deduplicate exactly like struct
    layouts do.
    """

    name: str
    size: int
    constants: list[EnumConstant] = field(default_factory=list)


@dataclass
class Extraction:
    """One extractor's full reading of one PDB."""

    extractor: str
    pdb_key: str
    types: dict[str, TypeLayout] = field(default_factory=dict)
    enums: dict[str, EnumDef] = field(default_factory=dict)
    rvas: dict[str, int] = field(default_factory=dict)
    missing_types: list[str] = field(default_factory=list)
    missing_symbols: list[str] = field(default_factory=list)
    missing_enums: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        payload = {
            "extractor": self.extractor,
            "pdb_key": self.pdb_key,
            # Canonical ordering (7.4): types by name, members by offset then
            # name. Both extractors must serialize identically or the hashes
            # diverge for reasons that have nothing to do with the layout.
            "types": {
                name: {
                    "size": layout.size,
                    "members": [asdict(m) for m in sorted(layout.members)],
                }
                for name, layout in sorted(self.types.items())
            },
            "enums": {
                name: {
                    "size": enum.size,
                    "constants": [
                        {"name": c.name, "value": c.value}
                        for c in sorted(enum.constants)
                    ],
                }
                for name, enum in sorted(self.enums.items())
            },
            "rvas": dict(sorted(self.rvas.items())),
            "missing_types": sorted(self.missing_types),
            "missing_symbols": sorted(self.missing_symbols),
            "missing_enums": sorted(self.missing_enums),
        }
        return json.dumps(payload, indent=2, sort_keys=False)

    def canonical_layout(self) -> bytes:
        """The exact bytes the layout hash is taken over (7.4).

        Deliberately not the JSON above. That form is for humans and diffing;
        this one has to stay stable against every incidental change in
        presentation, because a hash that moves when the formatting moves
        destroys the deduplication it exists to enable.

        RVAs are excluded on purpose: they differ in every build (6.2) and
        including them would give every build a unique hash, which is the one
        outcome content addressing must avoid.
        """
        lines: list[str] = []
        for name, layout in sorted(self.types.items()):
            lines.append(f"T {name} {layout.size}")
            for member in sorted(layout.members):
                lines.append(
                    f"M {member.offset} {member.name} {member.size} "
                    f"{member.bit_position} {member.bit_count}"
                )
        for name, enum in sorted(self.enums.items()):
            lines.append(f"E {name} {enum.size}")
            for constant in sorted(enum.constants):
                lines.append(f"C {constant.value} {constant.name}")
        return ("\n".join(lines) + "\n").encode("utf-8")

    def layout_hash(self) -> str:
        digest = hashlib.sha256(self.canonical_layout()).hexdigest()
        return f"v{LAYOUT_SCHEMA_VERSION}:sha256:{digest}"

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    @staticmethod
    def load(path: Path) -> "Extraction":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        result = Extraction(raw["extractor"], raw["pdb_key"])
        for name, body in raw["types"].items():
            result.types[name] = TypeLayout(
                name,
                body["size"],
                [Member(**m) for m in body["members"]],
            )
        for name, body in (raw.get("enums") or {}).items():
            result.enums[name] = EnumDef(
                name,
                body["size"],
                [EnumConstant(c["value"], c["name"]) for c in body["constants"]],
            )
        result.rvas = dict(raw.get("rvas", {}))
        result.missing_types = list(raw.get("missing_types", []))
        result.missing_symbols = list(raw.get("missing_symbols", []))
        result.missing_enums = list(raw.get("missing_enums", []))
        return result
