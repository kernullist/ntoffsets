"""The content-addressed store (7.2, 7.4).

Layouts are named by the hash of their own canonical form, so a build whose
struct layout has not changed writes no new layout file. Measured on 11-24H2:
58 consecutive builds produce 8 layouts, and 48 ARM64 builds produce 8. The
saving in bytes is real but secondary -- the operational point (8.4) is that
most days there is nothing to commit at all.

    types/v1/<sha256>.json     one type or enum, named by its own hash
    layouts/v1/<sha256>.json   a manifest: type name -> type hash
    symbols/universe.json      every symbol name ever seen, append-only
    builds/<guid><age>.json    a layout ref, a symbol bitmap, and the RVAs
    index/by-version.json      human-facing version -> keys
    index/coverage.json        what is missing and why (11)

Two rules keep the addressing honest:

* **The stored layout is derived only from what the hash covers.** Anything
  else -- `union_group`, for instance -- would let two builds that hash the
  same write different bytes to the same path, which is the one thing content
  addressing must not allow.
* **The schema version lives in the path, not in the hashed bytes** (M7).
  Changing the serialization changes every hash; putting the generation in
  `layouts/v1/` rather than inside the file keeps the two sets from mixing in
  one namespace.

**Addressing is per type, not per layout.** Hashing the whole set was right
while the set was 37 curated types: consecutive builds shared it outright, and
58 builds collapsed to 8 layouts. Extracting all 1,646 types and 408
enumerations broke that -- any one type moving makes the whole set unique, and
244 builds produced 128 layouts of 1.4 MB each, 180 MB in total and headed past
the hosting budget (8.4) well before the backfill finished.

Per type, the same data is 14 MB. There are 4,153 distinct type bodies behind
those 128 layouts, and after the first layout the *median* number of genuinely
new bodies per layout is zero: later layouts are recombinations, not rewrites.
A layout is now a manifest of hashes, and its own hash is unchanged -- still
taken over the full canonical form -- so build entries keep pointing at the
same identity.

It also makes the diff cheap. Comparing two layouts is comparing two lists of
hashes; only the types that actually differ need to be read.

RVAs cannot be content addressed -- every build has different ones, which is
the whole point of storing them. The *names* can be: they live once in an
append-only universe, and each build records which of them it has as a bitmap
(see `symbols.py`). That is 2.5 KiB per build instead of 254 KiB.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import symbols as symbol_universe
from .model import LAYOUT_SCHEMA_VERSION, Extraction, Member, TypeLayout

SOURCE = "winbindex+msdl"


def _hex(value: int) -> str:
    return f"0x{value:X}"


@dataclass
class WriteResult:
    layout_hash: str
    layout_written: bool


class Store:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.layouts = self.root / "layouts" / f"v{LAYOUT_SCHEMA_VERSION}"
        self.types = self.root / "types" / f"v{LAYOUT_SCHEMA_VERSION}"
        self.symbols = self.root / "symbols" / f"v{LAYOUT_SCHEMA_VERSION}"
        self.builds = self.root / "builds"
        self.index = self.root / "index"

    # -- layouts --------------------------------------------------------------

    # A 12 hex prefix distinguishes some thousands of blobs with room to
    # spare, and keeps a 2,000-entry manifest to about 60 KB rather than 130.
    HASH_PREFIX = 12

    @staticmethod
    def canonical_type(name: str, layout) -> bytes:
        lines = [f"T {name} {layout.size}"]
        for member in sorted(layout.members):
            lines.append(
                f"M {member.offset} {member.name} {member.size} "
                f"{member.bit_position} {member.bit_count} {member.type}"
            )
        return "\n".join(lines).encode("utf-8")

    @staticmethod
    def canonical_enum(name: str, enum) -> bytes:
        lines = [f"E {name} {enum.size}"]
        for constant in sorted(enum.constants):
            lines.append(f"C {constant.value} {constant.name}")
        return "\n".join(lines).encode("utf-8")

    @staticmethod
    def type_document(name: str, layout) -> dict:
        return {
            "name": name,
            "kind": "type",
            "size": layout.size,
            "members": [
                {
                    "name": m.name,
                    "type": m.type,
                    "offset": m.offset,
                    "size": m.size,
                    "bit_position": m.bit_position,
                    "bit_count": m.bit_count,
                }
                for m in sorted(layout.members)
            ],
        }

    @staticmethod
    def enum_document(name: str, enum) -> dict:
        return {
            "name": name,
            "kind": "enum",
            "size": enum.size,
            "constants": [
                {"name": c.name, "value": c.value} for c in sorted(enum.constants)
            ],
        }

    def _write_blob(self, canonical: bytes, document: dict) -> tuple[str, bool]:
        digest = hashlib.sha256(canonical).hexdigest()[: self.HASH_PREFIX]
        path = self.types / f"{digest}.json"
        if path.exists():
            return digest, False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
        return digest, True

    def read_type(self, digest: str) -> dict:
        return json.loads((self.types / f"{digest}.json").read_text(encoding="utf-8"))

    @staticmethod
    def layout_document(extraction: Extraction) -> dict:
        """The stored form: exactly the fields the hash is taken over.

        Members are ordered by offset then name, matching the canonical
        serialization, so the file is a pure function of the hash input.
        """
        return {
            "schema": LAYOUT_SCHEMA_VERSION,
            "hash": extraction.layout_hash(),
            "types": {
                name: {
                    "size": layout.size,
                    "members": [
                        {
                            "name": member.name,
                            "offset": member.offset,
                            "size": member.size,
                            "bit_position": member.bit_position,
                            "bit_count": member.bit_count,
                        }
                        for member in sorted(layout.members)
                    ],
                }
                for name, layout in sorted(extraction.types.items())
            },
            "enums": {
                name: {
                    "size": enum.size,
                    "constants": [
                        {"name": c.name, "value": c.value}
                        for c in sorted(enum.constants)
                    ],
                }
                for name, enum in sorted(extraction.enums.items())
            },
        }

    def write_layout(self, extraction: Extraction) -> WriteResult:
        """Write every type body that is new, then the manifest naming them.

        Blobs are written even when the manifest already exists, because a
        manifest can only be trusted if everything it points at is present --
        and an interrupted run is the normal case for a backfill.
        """
        digest = extraction.layout_hash()
        path = self.layouts / f"{digest.split(':')[-1]}.json"

        manifest_types: dict[str, str] = {}
        manifest_enums: dict[str, str] = {}
        for name, layout in sorted(extraction.types.items()):
            blob, _ = self._write_blob(
                self.canonical_type(name, layout), self.type_document(name, layout)
            )
            manifest_types[name] = blob
        for name, enum in sorted(extraction.enums.items()):
            blob, _ = self._write_blob(
                self.canonical_enum(name, enum), self.enum_document(name, enum)
            )
            manifest_enums[name] = blob

        if path.exists():
            return WriteResult(digest, False)

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": LAYOUT_SCHEMA_VERSION,
                    "hash": digest,
                    "types": manifest_types,
                    "enums": manifest_enums,
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        return WriteResult(digest, True)

    # -- symbols --------------------------------------------------------------

    @property
    def universe_path(self) -> Path:
        return self.root / "symbols" / "universe.json"

    def universe(self) -> symbol_universe.Universe:
        return symbol_universe.Universe(self.universe_path)

    # -- builds ---------------------------------------------------------------

    def write_build(self, candidate, key, extraction: Extraction, layout_hash: str,
                    file_name: str, universe: symbol_universe.Universe | None = None) -> Path:
        """One build entry, keyed by PDB GUID + Age (5.2, 5.3).

        `channel` and `kb` are lists because one binary ships under several of
        each. `timestamp` and `size_of_image` are hex strings per 5.3; RVAs
        follow suit, since nobody reads an RVA in decimal.
        """
        path = self.builds / f"{key.key}.json"
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

        def merge(field: str, values) -> list:
            previous = existing.get(field) or []
            if isinstance(previous, str):
                previous = [previous]
            return sorted(set(previous) | set(values))

        def keep(field: str, value):
            """Prefer what this run found, fall back to what is already stored.

            The same binary is indexed by more than one dataset and they do not
            carry the same metadata: the Insider index has no release dates at
            all and 79% of the ARM64 index has no version string (4.5). Writing
            the incoming value unconditionally means whichever dataset runs
            last decides, so a re-run in the order ga, arm64, insider erased
            the release date from 341 builds that GA had dated correctly.

            Resuming hid this -- a build already in the store was skipped, so
            the dateless pass never reached it. `--force` is what made it
            visible, which is the wrong thing to have to depend on.
            """
            return value if value else existing.get(field)

        sources = merge("sha256", [candidate.sha256])
        channels = merge("channel", candidate.channel_names)
        kbs = merge("kb", candidate.kbs)

        if universe is not None:
            symbol_bitmap, ordered, universe_size = symbol_universe.encode(
                universe, extraction.rvas
            )
            ordered_rvas = ordered
        else:
            symbol_bitmap, universe_size = None, 0
            ordered_rvas = [rva for _, rva in sorted(extraction.rvas.items())]

        document = {
            # Two spellings of the same identity, and they are not
            # interchangeable. `symbol_key` is msdl's: GUID hex followed by the
            # age in *hex*, and it is also this file's name and the API path
            # (8.1). `key` is 5.3's readable form with the age in *decimal*.
            # They coincide only while age < 10, which is every build seen so
            # far -- exactly the kind of latent trap that surfaces years later
            # in someone else's code.
            "key": f"{key.guid.hex.upper()}-{key.age}",
            "symbol_key": key.key,
            "pdb_guid": str(key.guid).upper(),
            "pdb_age": key.age,
            "pdb_name": key.pdb_name,
            "file_name": file_name,
            # Every Winbindex entry that resolves to this build. A list for
            # the same reason `channel` and `kb` are (5.3): one binary is
            # published under several hashes, and recording only the last one
            # left the others accounted for nowhere -- 84 index entries that
            # were neither stored nor missing, and a resumed run that flipped
            # which hash it kept.
            "sha256": sources,
            "file_version": keep("file_version", candidate.version),
            "machine": candidate.machine_name,
            "timestamp": keep("timestamp", _hex(candidate.timestamp)),
            "size_of_image": keep("size_of_image", _hex(candidate.size_of_image)),
            "channel": channels,
            "kb": kbs,
            "release_date": keep("release_date", candidate.release_date),
            "layout": layout_hash,
            # Which of the universe's names this build has, and their addresses
            # in the same order. `universe_size` is how many names existed when
            # this was written, so a bitmap stays readable as the universe grows.
            "symbols": symbol_bitmap,
            "universe_size": universe_size,
            "rva": [_hex(rva) for rva in ordered_rvas],
            "symbol_count": len(extraction.rvas),
            "missing_symbols": sorted(extraction.missing_symbols),
            "missing_types": sorted(extraction.missing_types),
            "missing_enums": sorted(extraction.missing_enums),
            "source": SOURCE,
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=1), encoding="utf-8")
        return path

    def read_manifest(self, digest: str) -> dict:
        path = self.layouts / f"{digest.split(':')[-1]}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def read_layout(self, digest: str) -> dict:
        """Reassemble a whole layout. Prefer `read_manifest` where possible --
        this reads a couple of thousand small files."""
        manifest = self.read_manifest(digest)
        return {
            "schema": manifest["schema"],
            "hash": manifest["hash"],
            "types": {
                name: self.read_type(blob)
                for name, blob in manifest.get("types", {}).items()
            },
            "enums": {
                name: self.read_type(blob)
                for name, blob in manifest.get("enums", {}).items()
            },
        }

    def layout_types(self, digest: str) -> dict[str, TypeLayout]:
        """Rebuild a layout's types as the model, for a build we did not extract.

        The continuity check needs a build's neighbours (13.4), and on an
        incremental run the neighbour was collected weeks ago and is only in
        the store. Without this the check silently compares new builds to each
        other and reports nothing, which is the shape of a check that has
        stopped checking.

        Types only: continuity reads sizes and member offsets and nothing else,
        and the enums would double the reads for no one.
        """
        manifest = self.read_manifest(digest)
        types: dict[str, TypeLayout] = {}
        for name, blob in (manifest.get("types") or {}).items():
            body = self.read_type(blob)
            types[name] = TypeLayout(
                name,
                body["size"],
                [
                    Member(
                        offset=m["offset"], name=m["name"], size=m["size"],
                        bit_position=m["bit_position"], bit_count=m["bit_count"],
                        type=m.get("type", ""),
                    )
                    for m in body["members"]
                ],
            )
        return types

    def known_sources(self) -> set[str]:
        """Every Winbindex hash already represented in the store."""
        found: set[str] = set()
        for build in self.read_builds():
            value = build.get("sha256")
            if isinstance(value, str):
                found.add(value)
            elif value:
                found.update(value)
        return found

    def read_builds(self) -> list[dict]:
        if not self.builds.is_dir():
            return []
        return [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(self.builds.glob("*.json"))
        ]

    # -- indexes --------------------------------------------------------------

    def rebuild_indexes(self) -> dict:
        """Regenerate the derived indexes from the build files.

        Derived rather than incremental on purpose: the build files are the
        only source of truth, so an index can never drift from them.
        """
        builds = self.read_builds()

        by_version: dict[str, list[str]] = {}
        for build in builds:
            version = build.get("file_version")
            if not version:
                # 79% of ARM64 entries have no version string (4.5). Their
                # lookups go through the PDB key or the KB number instead.
                continue
            by_version.setdefault(version, []).append(
                build.get("symbol_key") or build["key"].replace("-", "")
            )

        document = {
            "schema": 1,
            "count": len(by_version),
            "versions": {
                version: sorted(keys) for version, keys in sorted(by_version.items())
            },
        }
        self.index.mkdir(parents=True, exist_ok=True)
        (self.index / "by-version.json").write_text(
            json.dumps(document, indent=1), encoding="utf-8"
        )
        return document

    # -- stats ----------------------------------------------------------------

    def stats(self) -> dict:
        layouts = list(self.layouts.glob("*.json")) if self.layouts.is_dir() else []
        builds = list(self.builds.glob("*.json")) if self.builds.is_dir() else []
        blobs = list(self.types.glob("*.json")) if self.types.is_dir() else []
        universe = self.universe_path
        return {
            "builds": len(builds),
            "layouts": len(layouts),
            "type_blobs": len(blobs),
            "universe_names": len(self.universe()) if universe.exists() else 0,
            "layout_bytes": sum(p.stat().st_size for p in layouts),
            "type_bytes": sum(p.stat().st_size for p in blobs),
            "build_bytes": sum(p.stat().st_size for p in builds),
            "symbol_bytes": universe.stat().st_size if universe.exists() else 0,
        }
