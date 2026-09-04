"""Coverage reporting (11).

The differentiator against Vergilius is not having more data. It is saying
which data we do not have, and why. A gap that is recorded is a coverage
number; a gap that is silent is a bug report waiting to happen.

That principle constrains how the numbers are kept. Tallying per run would be
easy and wrong: re-running a channel would double count its failures, and
re-running a subset would erase the rest. So unresolved builds are recorded
**per content hash**, and a later run that succeeds clears the entry. The
report is then a function of the store's current state rather than of whichever
command happened to run last.

Two reason codes came out of the spike rather than the original design:

* `no_version_metadata` -- 79% of ARM64 index entries carry no version string
  (4.5). Lookups by PDB key are unaffected, but version-based lookup will be
  mostly empty there, and that is a property of the input, not a fault.
* `undownloadable` -- index entries with no timestamp or image size, so no
  msdl URL can be constructed at all.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Not an absence at all: this index entry names a build we already hold under
# another entry, because one binary ships under several hashes.
COVERED_ELSEWHERE = "duplicate_key"

# Ordinary absences, expected and recorded (4.2).
COVERAGE_REASONS = (
    "binary_404",       # msdl has no binary under this key
    "pdb_404",          # binary resolved, but no symbols published
    "undownloadable",   # index entry lacks timestamp or image size
    "excluded_arch",
)

# Our faults, not gaps in the input. These go to the bug queue (11).
DEFECT_REASONS = (
    "pe_parse_failed",
    "parse_failed",
    "inconsistent",
    "oracle_mismatch",
)

TRANSIENT_REASONS = ("fetch_error",)


class Ledger:
    """Per-build record of everything that did not make it into the store."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, dict] = {}
        if path.exists():
            self.entries = json.loads(path.read_text(encoding="utf-8"))

    def record(self, sha256: str, reason: str, dataset: str, candidate) -> None:
        self.entries[sha256] = {
            "reason": reason,
            "dataset": dataset,
            "version": candidate.version or None,
            "channel": candidate.channel_names,
            "machine": candidate.machine_name,
        }

    def clear(self, sha256: str) -> None:
        self.entries.pop(sha256, None)

    def counts(self) -> dict[str, int]:
        return dict(sorted(Counter(e["reason"] for e in self.entries.values()).items()))

    def defects(self) -> list[dict]:
        return [e for e in self.entries.values() if e["reason"] in DEFECT_REASONS]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(dict(sorted(self.entries.items())), indent=1), encoding="utf-8"
        )


def merge_dataset(path: Path, name: str, known: int, downloadable: int,
                  channels: dict[str, int] | None = None) -> dict:
    """Record how large each dataset is, so `known` survives partial runs."""
    datasets = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    datasets[name] = {"known": known, "downloadable": downloadable,
                      "channels": channels or {}}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(sorted(datasets.items())), indent=1), encoding="utf-8")
    return datasets


def set_universe(path: Path, file_name: str, distinct: int) -> None:
    """Record how many *distinct* binaries the datasets describe between them.

    The datasets overlap: 84 of the Insider entries for `ntoskrnl.exe` are the
    same binaries that later shipped as GA, listed in both indexes. Summing the
    per-dataset totals counted them twice and made the denominator 2,238 when
    only 2,154 files exist -- understating coverage by four points and leaving
    84 builds looking permanently unattempted when nothing was missing at all.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema": 1, "file": file_name, "known_distinct": distinct}, indent=1),
        encoding="utf-8",
    )


def build_report(datasets: dict[str, dict], builds: list[dict], ledger: Ledger,
                 known_distinct: int | None = None) -> dict:
    # Per-dataset totals still describe each dataset; the denominator is the
    # union, because a build listed twice is still one build.
    known = known_distinct or sum(d.get("known", 0) for d in datasets.values())
    resolved = len(builds)

    by_channel: dict[str, dict[str, int]] = {}
    by_machine: Counter[str] = Counter()
    no_version = 0

    # Seed from the index so a channel we have never collected reads as
    # "0 of 121", not as a near-complete channel with one gap.
    for data in datasets.values():
        for channel, total in (data.get("channels") or {}).items():
            bucket = by_channel.setdefault(channel, {"resolved": 0})
            bucket["known"] = bucket.get("known", 0) + total

    for build in builds:
        by_machine[build["machine"]] += 1
        if not build.get("file_version"):
            no_version += 1
        for channel in build.get("channel") or ["unknown"]:
            by_channel.setdefault(channel, {"resolved": 0})["resolved"] += 1

    for entry in ledger.entries.values():
        if entry["reason"] == COVERED_ELSEWHERE:
            continue
        for channel in entry.get("channel") or ["unknown"]:
            bucket = by_channel.setdefault(channel, {"resolved": 0})
            bucket["missing"] = bucket.get("missing", 0) + 1

    reasons = ledger.counts()
    duplicates = reasons.pop(COVERED_ELSEWHERE, 0)
    for bucket in by_channel.values():
        bucket.setdefault("known", 0)
        bucket.setdefault("missing", 0)
        bucket["unattempted"] = max(
            bucket["known"] - bucket["resolved"] - bucket["missing"], 0
        )

    return {
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totals": {
            "known": known,
            "resolved": resolved,
            "accounted_missing": sum(reasons.values()),
            # Index entries that resolve to a build already held under another
            # entry. Counted apart from both: they are neither a gap nor a
            # separate build.
            "duplicate_entries": duplicates,
            "unattempted": max(
                known - resolved - sum(reasons.values()) - duplicates, 0
            ),
        },
        "missing_reasons": reasons,
        # Defects are ours to fix, not gaps in the input. Kept separate so the
        # number cannot hide inside a coverage total.
        "defects": len(ledger.defects()),
        # Not missing: these builds are fully resolved but cannot be found by
        # version string (4.5).
        "no_version_metadata": no_version,
        "by_dataset": dict(sorted(datasets.items())),
        "by_machine": dict(sorted(by_machine.items())),
        "by_channel": dict(sorted(by_channel.items())),
    }


def write(report: dict, index_dir: Path) -> Path:
    index_dir.mkdir(parents=True, exist_ok=True)
    path = index_dir / "coverage.json"
    path.write_text(json.dumps(report, indent=1), encoding="utf-8")
    return path
