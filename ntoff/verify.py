"""Reproducibility check (8.6).

The claim this project makes is that a number in the database is the number in
the PDB. `verify` is how someone who does not take our word for it settles the
question: fetch the PDB from Microsoft, extract it again, and compare against
what we published.

Two things make that meaningful rather than ceremonial.

**It reads the published artifacts, not the store.** Verifying our own working
copy would only prove the store is self-consistent, which is a different and
much weaker claim. So the source is the API shape a consumer actually fetches
-- `v1/build/…`, `v1/layout/…`, `v1/type/…`, `v1/symbols/universe.json` --
and it works against a URL as readily as a directory.

**It recomputes the addressing rather than trusting it.** A layout is named by
the hash of its own canonical form (7.4); verify recomputes that hash from the
re-extraction and checks the published name matches, then checks the published
bytes match what the hash promises. Comparing only the content would miss a
layout filed under the wrong name; comparing only the name would miss content
that does not match it.

The symbol bitmap gets the same treatment. Its whole design (7.5) is positional
-- the nth set bit names the nth address -- and a positional encoding that is
off by one is the failure this project exists to avoid, so verify decodes it
and compares name to address, not bitmap to bitmap.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import msdl, symbols as symbol_universe
from .model import Extraction
from .store import Store


class Source:
    """Reads the published API, from a directory or over HTTP."""

    def __init__(self, location: str) -> None:
        self.location = location.rstrip("/")
        self.remote = location.startswith(("http://", "https://"))

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.location

    def get(self, path: str) -> dict:
        if self.remote:
            request = urllib.request.Request(
                f"{self.location}/{path}",
                headers={"User-Agent": "ntoff-verify/1.0"},
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        return json.loads((Path(self.location) / path).read_text(encoding="utf-8"))

    def build(self, key: str) -> dict:
        return self.get(f"v1/build/{key}.json")

    def manifest(self, layout: str) -> dict:
        return self.get(f"v1/layout/{layout.split(':')[-1]}.json")

    def type_blob(self, digest: str) -> dict:
        return self.get(f"v1/type/{digest}.json")

    def universe(self) -> list[str]:
        return self.get("v1/symbols/universe.json")["names"]

    def keys(self) -> list[str]:
        return [b["k"] for b in self.get("v1/index/builds.json")["builds"]]


@dataclass
class Result:
    key: str
    version: str = ""
    checked_types: int = 0
    checked_enums: int = 0
    checked_symbols: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.problems


def verify_build(source: Source, key: str, extraction: Extraction) -> Result:
    """Compare a fresh extraction against everything published for `key`."""
    published = source.build(key)
    result = Result(key, published.get("file_version") or key[:12])

    # --- the layout is named by its own content -----------------------------
    recomputed = extraction.layout_hash()
    if recomputed != published["layout"]:
        result.problems.append(
            f"layout hash {recomputed} != published {published['layout']}"
        )
        # Everything below compares against a layout we have just shown is the
        # wrong one, so there is nothing further to learn here.
        return result

    manifest = source.manifest(published["layout"])
    _verify_members(source, manifest, extraction, result)
    _verify_enums(source, manifest, extraction, result)
    _verify_symbols(source, published, extraction, result)
    return result


def _verify_members(source: Source, manifest: dict, extraction: Extraction,
                    result: Result) -> None:
    listed = manifest.get("types") or {}
    ours = extraction.types

    for name in sorted(set(listed) | set(ours)):
        if name not in listed:
            result.problems.append(f"{name}: extracted but not published")
            continue
        if name not in ours:
            result.problems.append(f"{name}: published but not in the extraction")
            continue

        result.checked_types += 1
        digest = Store.canonical_type(name, ours[name])
        expected = hashlib.sha256(digest).hexdigest()[: Store.HASH_PREFIX]
        if expected != listed[name]:
            result.problems.append(
                f"{name}: content hash {expected} != manifest {listed[name]}"
            )
            continue

        blob = source.type_blob(listed[name])
        if blob != Store.type_document(name, ours[name]):
            # The hash matched, so this means the stored bytes are not what the
            # hash was taken over -- the addressing itself is broken.
            result.problems.append(f"{name}: published body differs from its own hash")


def _verify_enums(source: Source, manifest: dict, extraction: Extraction,
                  result: Result) -> None:
    listed = manifest.get("enums") or {}
    ours = extraction.enums

    for name in sorted(set(listed) | set(ours)):
        if name not in listed:
            result.problems.append(f"{name}: enum extracted but not published")
            continue
        if name not in ours:
            result.problems.append(f"{name}: enum published but not in the extraction")
            continue

        result.checked_enums += 1
        digest = Store.canonical_enum(name, ours[name])
        expected = hashlib.sha256(digest).hexdigest()[: Store.HASH_PREFIX]
        if expected != listed[name]:
            result.problems.append(
                f"{name}: enum hash {expected} != manifest {listed[name]}"
            )
            continue

        blob = source.type_blob(listed[name])
        if blob != Store.enum_document(name, ours[name]):
            result.problems.append(f"{name}: published enum differs from its own hash")


def _verify_symbols(source: Source, published: dict, extraction: Extraction,
                    result: Result) -> None:
    """Decode the bitmap and compare name to address.

    Not bitmap to bitmap: the encoding is positional, and two different
    bitmaps can describe the same mapping while one wrong bit shifts every
    pair after it. What has to hold is the mapping.
    """
    rvas = published.get("rva")
    if isinstance(rvas, dict):
        decoded = {name: int(value, 16) for name, value in rvas.items()}
    else:
        universe = symbol_universe.Universe(Path("/nonexistent"))
        universe.names = source.universe()
        decoded = symbol_universe.decode(
            universe, published["symbols"], [int(v, 16) for v in rvas]
        )

    ours = extraction.rvas
    result.checked_symbols = len(ours)

    missing = sorted(set(ours) - set(decoded))
    extra = sorted(set(decoded) - set(ours))
    if missing:
        result.problems.append(
            f"{len(missing)} symbol(s) extracted but not published, e.g. {missing[:3]}"
        )
    if extra:
        result.problems.append(
            f"{len(extra)} symbol(s) published but not extracted, e.g. {extra[:3]}"
        )
    wrong = [n for n in set(ours) & set(decoded) if ours[n] != decoded[n]]
    for name in sorted(wrong)[:5]:
        result.problems.append(
            f"{name}: RVA {decoded[name]:#x} published, {ours[name]:#x} extracted"
        )
    if len(wrong) > 5:
        result.problems.append(f"... and {len(wrong) - 5} more RVA mismatches")


def fetch_pdb_for(published: dict, cache: Path) -> msdl.FetchResult:
    """Get the PDB the published entry names, from Microsoft.

    The cache is keyed by the same PDB key the symbol server is, and a PDB is
    immutable for a given key, so a cache hit verifies exactly what a fresh
    download would. `--no-cache` exists for anyone who would rather not take
    that on trust either.
    """
    return msdl.fetch_pdb(published["pdb_name"], published["symbol_key"], cache)
