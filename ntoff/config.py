"""Reads types.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "types.toml"


@dataclass(frozen=True)
class Allowlist:
    """What to extract.

    The original design curated a type list because a full dump was assumed to
    be over ten thousand types and impractical (6). Measured, a kernel PDB holds
    1,646 struct and union definitions, 408 enumerations and about 10,000 plain
    global symbols -- 1.5 MB, 200 KB and 385 KB of compact JSON respectively.
    Curation was solving a problem that does not exist, and it cost coverage:
    37 of 1,646 types and 16 of 10,000 symbols.

    So extraction takes everything. The curated lists stay for the jobs that
    genuinely need a subset -- the bitfield gate, and header generation for a
    driver that wants five offsets rather than sixteen thousand.
    """

    types: tuple[str, ...]
    gate_types: tuple[str, ...]
    symbols: tuple[str, ...]
    curated_types: tuple[str, ...] = ()
    curated_symbols: tuple[str, ...] = ()


def load(path: Path | None = None) -> Allowlist:
    document = tomllib.loads((path or DEFAULT_PATH).read_text(encoding="utf-8"))
    groups = document["types"]
    gate = tuple(groups.get("gate", ()))
    types = {name for key, names in groups.items() if key != "gate" for name in names}
    types.update(gate)
    symbols = {name for names in document["symbols"].values() for name in names}
    extract = document.get("extract", {})
    return Allowlist(
        types=tuple(extract.get("types", ["*"])),
        gate_types=gate,
        symbols=tuple(extract.get("symbols", ["*"])),
        curated_types=tuple(sorted(types)),
        curated_symbols=tuple(sorted(symbols)),
    )


def enums(path: Path | None = None) -> tuple[str, ...]:
    document = tomllib.loads((path or DEFAULT_PATH).read_text(encoding="utf-8"))
    return tuple(document.get("extract", {}).get("enums", ["*"]))
