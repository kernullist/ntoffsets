"""The diff feed (10).

This is the only genuinely new thing here. A file-identity layer can say "a new
kernel shipped"; saying "and `_EPROCESS` grew eight bytes in it" needs the
parsing, which is the whole reason for the layer above (2.4).

Its value is not novelty though, it is **reliability as a regression trigger**
(10.1). Kernel structs do not change most months, and `"types_changed": []` is
the answer most of the time. That is not a dull feed, it is a green light: wire
this into CI and patch Tuesday either says nothing moved, or names exactly which
types did so the drivers that use them get retested.

Two things decide whether the output means anything:

**What counts as adjacent.** Only consecutive builds within one channel *and*
one architecture. Both axes are load-bearing, and both were learned by getting
them wrong in the continuity check (13.4): `_KPRCB` legitimately moves tens of
kilobytes between Windows versions, and 22000 amd64 versus 22000 ARM64 share a
version number and almost no layout.

**How they are ordered.** Not by PE timestamp -- deterministic builds put a
content hash in that field, and sorting on it produces dates in 1978 and 2103.
Not by version alone either, since 79% of ARM64 index entries have none (4.5).
The key is `(release_date, version)`, which is available for every build with a
KB and agrees with version order wherever both exist.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from . import version

FEED_SCHEMA = 1
FEED_ID = "urn:ntoffsets:feed:changes"


def order_key(build: dict) -> tuple:
    return (build.get("release_date") or "",
            version.sort_key(build.get("file_version")),
            build.get("symbol_key") or "")


def sequences(builds: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Group builds into ordered runs of genuinely adjacent releases.

    Keyed by channel and machine (13.4), and by Windows version too wherever
    the channel does not already imply one -- see `version.mixed_channels` for
    why the label alone is not enough.

    A build shipped in several channels appears in each of their sequences,
    which is correct: it really is the neighbour of a different build in each.
    A build whose channel is mixed and which carries no version string is left
    out, because there is nothing to place it against.

    This is the only definition of "adjacent" in the codebase. The continuity
    check (13.4) reads it from here rather than deciding again.
    """
    mixed = version.mixed_channels(
        (build.get("channel") or [], build.get("file_version")) for build in builds
    )
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for build in builds:
        for channel in build.get("channel") or ["unknown"]:
            label = version.channel_label(channel, build.get("file_version"), mixed)
            if label is not None:
                grouped[(label, build["machine"])].append(build)

    return {
        key: sorted(items, key=_sequence_order(items))
        for key, items in sorted(grouped.items())
    }


def _sequence_order(builds: list[dict]):
    """Order one sequence by whichever signal is complete across it.

    `order_key` leads with the release date, which is right when every build
    has one and wrong when they do not: a missing date becomes `""` and sorts
    the build to the front, so 26100.9233 landed next to 26100.1742 and the
    continuity check reported a `_KPRCB` member moving 0x2afc between them.
    Nothing moved. They are years apart and were never neighbours.

    Inside a sequence the channel already pins one Windows version, so when
    every build carries a version string that ordering is total and exact. The
    date leads only where it has to -- the ARM64 index has no version for 79%
    of its entries (4.5), and there the date is the only signal there is.
    """
    if all(build.get("file_version") for build in builds):
        return lambda build: (version.sort_key(build["file_version"]),
                              build.get("release_date") or "",
                              build.get("symbol_key") or "")
    return order_key


# ---------------------------------------------------------------------------
# layout comparison
# ---------------------------------------------------------------------------


# Names Microsoft uses for storage that is reserved rather than meaningful:
# `PrcbPad12`, `SpareByte0`, `MmReserved2`, `Flags2Available1`, `ReservedFlags`.
#
# Two shapes, and they are not symmetric.
#
# *Suffix*: the filler word ends the name, give or take a width word, a counter
# and a disambiguating letter. Allowing arbitrary text after it was the first
# attempt and it swallowed `AvailableTime` and `PadNumber`, both real fields.
#
# *Prefix*: `ReservedFlags`, `ReservedForHardware`, `SpareUlong`. Only some of
# the words work this way -- `Available...` and `Pad...` lead real field names,
# `Reserved...` and `Spare...` do not.
#
# Where the two rules disagree, treat the name as filler. Suppressing an alias
# costs a consumer one build check; emitting a wrong one sends them to a field
# whose meaning changed under the name they asked for, which is the failure
# this whole project is organised against.
FILLER_SUFFIX = re.compile(
    r"(Spare|Padding|Pad|Reserved|Available|Unused|Filler)"
    r"(Bytes?|Words?|Longs?|Ptrs?|Bits?|Dword|Qword|Uchar|Ulong|Ushort)?"
    r"\d*[a-z]?$"
)
FILLER_PREFIX = re.compile(r"^(Reserved|Spare|Unused|Padding|Filler)[A-Z0-9_]")


def is_filler(name: str) -> bool:
    return bool(FILLER_SUFFIX.search(name) or FILLER_PREFIX.match(name))


@dataclass
class Rename:
    type_name: str
    old: str
    new: str
    offset: int
    size: int
    bit_position: int
    bit_count: int

    @property
    def kind(self) -> str:
        """Why the same bytes changed name, which decides whether to alias them.

        A rename means the field kept its meaning and only its label moved --
        `MitigationFlags` to `MitigationFlags2`. Aliasing those is free and
        saves every consumer a build check (10.2).

        Filler is different. `ProcessExecutionState` becoming
        `Flags2Available1` is a field being *retired*: the bytes are still
        there, they no longer mean anything, and a caller who follows the alias
        reads a value that stopped being true. The reverse -- `PrcbPad139c`
        becoming `RawRelativePerformance` -- is padding acquiring a meaning it
        never had. Neither is a label change, and neither should be aliased on
        our say-so.
        """
        old_filler, new_filler = is_filler(self.old), is_filler(self.new)
        if old_filler and new_filler:
            return "padding_shuffle"
        if old_filler or new_filler:
            return "repurposed"
        return "rename"


def _members(layout: dict) -> dict[str, dict]:
    return {member["name"]: member for member in layout["members"]}


def _signature(member: dict) -> tuple[int, int, int, int]:
    return (member["offset"], member["size"],
            member["bit_position"], member["bit_count"])


def detect_renames(type_name: str, removed: dict[str, dict], added: dict[str, dict]
                   ) -> tuple[list[Rename], list[dict]]:
    """Pair a removed member with an added one at the identical position (10.2).

    A rename otherwise shows up as one removal plus one addition, and a caller
    hashing the old name gets `STATUS_NOT_FOUND` with nothing explaining why.

    Only unambiguous pairs are confirmed. When two members are removed and two
    added at the same offset and width, there is no way to tell which became
    which, and guessing would put a wrong alias into the blob -- so those go to
    a review queue instead. Being unable to answer is fine; answering wrongly
    is not.
    """
    by_signature: dict[tuple, dict[str, list[str]]] = defaultdict(
        lambda: {"removed": [], "added": []}
    )
    for name, member in removed.items():
        by_signature[_signature(member)]["removed"].append(name)
    for name, member in added.items():
        by_signature[_signature(member)]["added"].append(name)

    confirmed: list[Rename] = []
    ambiguous: list[dict] = []

    for signature, group in sorted(by_signature.items()):
        if not group["removed"] or not group["added"]:
            continue
        offset, size, bit_position, bit_count = signature
        if len(group["removed"]) == 1 and len(group["added"]) == 1:
            confirmed.append(Rename(type_name, group["removed"][0], group["added"][0],
                                    offset, size, bit_position, bit_count))
        else:
            ambiguous.append({
                "type": type_name,
                "removed": sorted(group["removed"]),
                "added": sorted(group["added"]),
                "offset": offset,
                "size": size,
                "bit_position": bit_position,
                "bit_count": bit_count,
            })

    return confirmed, ambiguous


def diff_enums(before: dict, after: dict) -> list[dict]:
    """Constants added, removed or renumbered.

    A struct offset moving breaks a read; a constant being renumbered breaks a
    comparison, which is quieter and just as wrong. `PS_PROTECTED_TYPE` gaining
    a level matters to anything that switches on it.
    """
    changes: list[dict] = []
    old_enums = before.get("enums") or {}
    new_enums = after.get("enums") or {}

    for name in sorted(set(old_enums) | set(new_enums)):
        old = old_enums.get(name)
        new = new_enums.get(name)
        if old is None or new is None:
            changes.append({"enum": name,
                            "status": "added" if old is None else "removed"})
            continue

        was = {c["name"]: c["value"] for c in old["constants"]}
        now = {c["name"]: c["value"] for c in new["constants"]}
        added = sorted(set(now) - set(was))
        removed = sorted(set(was) - set(now))
        renumbered = [
            {"name": k, "from": was[k], "to": now[k]}
            for k in sorted(set(was) & set(now)) if was[k] != now[k]
        ]
        if added or removed or renumbered or old["size"] != new["size"]:
            changes.append({
                "enum": name,
                "size_from": old["size"],
                "size_to": new["size"],
                "constants_added": added,
                "constants_removed": removed,
                "constants_renumbered": renumbered,
            })
    return changes


def diff_types(before: dict, after: dict) -> tuple[list[dict], list[Rename], list[dict]]:
    """Compare two layout documents, type by type."""
    changes: list[dict] = []
    renames: list[Rename] = []
    ambiguous: list[dict] = []

    for name in sorted(set(before["types"]) | set(after["types"])):
        old = before["types"].get(name)
        new = after["types"].get(name)

        if old is None or new is None:
            changes.append({
                "type": name,
                "status": "added" if old is None else "removed",
                "size_from": old["size"] if old else None,
                "size_to": new["size"] if new else None,
            })
            continue

        old_members = _members(old)
        new_members = _members(new)
        removed = {n: m for n, m in old_members.items() if n not in new_members}
        added = {n: m for n, m in new_members.items() if n not in old_members}

        confirmed, unclear = detect_renames(name, removed, added)
        renamed_old = {r.old for r in confirmed}
        renamed_new = {r.new for r in confirmed}
        renames.extend(confirmed)
        ambiguous.extend(unclear)

        moved, resized, rebitted, retyped = [], [], [], []
        for member_name in sorted(set(old_members) & set(new_members)):
            was, now = old_members[member_name], new_members[member_name]
            if was["offset"] != now["offset"]:
                moved.append({"name": member_name,
                              "from": was["offset"], "to": now["offset"]})
            if was["size"] != now["size"]:
                # Same address, different width: a caller that reads the old
                # number of bytes now reads past the member, or short of it.
                resized.append({"name": member_name,
                                "from": was["size"], "to": now["size"]})
            if was.get("type") and now.get("type") and was["type"] != now["type"]:
                # Same address, same width, different meaning: `void *` became
                # `_EPROCESS *`, or a reserved field acquired a real type. The
                # offset diff shows nothing at all, which is exactly the kind
                # of change 10.1 calls silently breaking.
                retyped.append({"name": member_name,
                                "from": was["type"], "to": now["type"]})
            if (was["bit_position"], was["bit_count"]) != (now["bit_position"], now["bit_count"]):
                rebitted.append({
                    "name": member_name,
                    "from": f"{was['bit_position']}:{was['bit_count']}",
                    "to": f"{now['bit_position']}:{now['bit_count']}",
                })

        entry = {
            "type": name,
            "size_from": old["size"],
            "size_to": new["size"],
            "members_added": sorted(n for n in added if n not in renamed_new),
            "members_removed": sorted(n for n in removed if n not in renamed_old),
            "members_moved": moved,
            "members_resized": resized,
            "members_rebitted": rebitted,
            "members_retyped": retyped,
            "members_renamed": [
                {"from": r.old, "to": r.new, "offset": r.offset, "size": r.size}
                for r in confirmed
            ],
        }
        if old["size"] != new["size"] or any(
            entry[k] for k in ("members_added", "members_removed", "members_moved",
                               "members_resized", "members_rebitted", "members_retyped",
                               "members_renamed")
        ):
            changes.append(entry)

    return changes, renames, ambiguous


# ---------------------------------------------------------------------------
# feed
# ---------------------------------------------------------------------------


@dataclass
class Feed:
    changes: list[dict] = field(default_factory=list)
    sequences: list[dict] = field(default_factory=list)
    renames: list[Rename] = field(default_factory=list)
    ambiguous: list[dict] = field(default_factory=list)


def build_feed(store, coverage_report: dict | None = None) -> Feed:
    builds = store.read_builds()
    manifests: dict[str, dict] = {}
    blobs: dict[str, dict] = {}

    def manifest_of(digest: str) -> dict:
        if digest not in manifests:
            manifests[digest] = store.read_manifest(digest)
        return manifests[digest]

    def blob_of(digest: str) -> dict:
        if digest not in blobs:
            blobs[digest] = store.read_type(digest)
        return blobs[digest]

    def changed_only(before_digest: str, after_digest: str, section: str) -> tuple[dict, dict]:
        """Reassemble just the entries whose hashes differ.

        Two layouts share almost every type; comparing them in full would read
        four thousand files to find a handful of differences.
        """
        old = manifest_of(before_digest).get(section, {})
        new = manifest_of(after_digest).get(section, {})
        names = {n for n in set(old) | set(new) if old.get(n) != new.get(n)}
        return (
            {n: blob_of(old[n]) for n in names if n in old},
            {n: blob_of(new[n]) for n in names if n in new},
        )

    feed = Feed()
    by_channel = (coverage_report or {}).get("by_channel", {})

    for (channel, machine), run in sequences(builds).items():
        transitions = changed = 0

        for before, after in zip(run, run[1:]):
            transitions += 1
            if before["layout"] == after["layout"]:
                continue
            changed += 1

            old_types, new_types = changed_only(before["layout"], after["layout"], "types")
            old_enums, new_enums = changed_only(before["layout"], after["layout"], "enums")
            types_changed, renames, ambiguous = diff_types(
                {"types": old_types}, {"types": new_types}
            )
            enums_changed = diff_enums({"enums": old_enums}, {"enums": new_enums})
            feed.renames.extend(renames)
            feed.ambiguous.extend(ambiguous)
            feed.changes.append({
                "channel": channel,
                "machine": machine,
                "from_version": before.get("file_version"),
                "to_version": after.get("file_version"),
                "from_key": before.get("symbol_key"),
                "to_key": after.get("symbol_key"),
                "from_kb": before.get("kb") or [],
                "kb": after.get("kb") or [],
                "date": after.get("release_date"),
                "layout_from": before["layout"],
                "layout_to": after["layout"],
                "types_changed": types_changed,
                "enums_changed": enums_changed,
            })

        feed.sequences.append({
            "channel": channel,
            "machine": machine,
            "builds": len(run),
            "transitions": transitions,
            "layout_changes": changed,
            "from_version": run[0].get("file_version"),
            "to_version": run[-1].get("file_version"),
            "from_date": run[0].get("release_date"),
            "to_date": run[-1].get("release_date"),
            "latest_layout": run[-1]["layout"],
            # Transitions are between builds we hold, not between every build
            # that exists. A consumer treating this as a regression trigger has
            # to know whether the run has holes in it (11).
            "known_missing_in_channel": by_channel.get(channel, {}).get("missing", 0),
        })

    feed.changes.sort(key=lambda c: (c.get("date") or "", c["channel"], c["machine"]),
                      reverse=True)
    return feed


def feed_document(feed: Feed) -> dict:
    return {
        "schema": FEED_SCHEMA,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sequences": feed.sequences,
        "changes": feed.changes,
    }


def aliases_document(existing: dict | None, feed: Feed) -> dict:
    """Accumulate confirmed renames (10.2).

    The blob packer emits a field entry under both names, so a caller does not
    have to branch on build. The cost is a couple of extra entries; the benefit
    is that the rename stops being an unexplained `STATUS_NOT_FOUND`.
    """
    entries = {
        (a["type"], a["from"], a["to"]): a
        for a in (existing or {}).get("aliases", [])
    }
    for rename in feed.renames:
        if rename.kind != "rename":
            continue
        key = (rename.type_name, rename.old, rename.new)
        entry = entries.setdefault(key, {
            "type": rename.type_name,
            "from": rename.old,
            "to": rename.new,
            "offset": rename.offset,
            "size": rename.size,
            "bit_position": rename.bit_position,
            "bit_count": rename.bit_count,
            "observations": 0,
        })
        # How many independent (channel, architecture) sequences produced the
        # same pairing. One is enough to be plausible; several across
        # architectures is corroboration a reviewer can weigh.
        entry["observations"] = entry.get("observations", 0) + 1
    return {
        "schema": 1,
        "count": len(entries),
        "aliases": [entries[k] for k in sorted(entries)],
    }


def review_document(feed: Feed) -> dict:
    """Everything the heuristic found but will not act on alone (10.2).

    Two populations, for different reasons. Ambiguous pairings cannot be
    resolved at all. Filler transitions can be read perfectly well -- they are
    just not renames, and aliasing them would point a caller at bytes whose
    meaning changed underneath the name.
    """
    ambiguous = {json.dumps(item, sort_keys=True): item for item in feed.ambiguous}
    filler: dict[tuple, dict] = {}
    for rename in feed.renames:
        if rename.kind == "rename":
            continue
        entry = filler.setdefault((rename.type_name, rename.old, rename.new), {
            "type": rename.type_name,
            "from": rename.old,
            "to": rename.new,
            "offset": rename.offset,
            "size": rename.size,
            "bit_position": rename.bit_position,
            "bit_count": rename.bit_count,
            "kind": rename.kind,
            "observations": 0,
        })
        entry["observations"] += 1

    return {
        "schema": 1,
        "ambiguous": {
            "count": len(ambiguous),
            "note": "same offset and width, but not a 1:1 pairing; "
                    "no way to tell which member became which",
            "candidates": [ambiguous[k] for k in sorted(ambiguous)],
        },
        "not_a_rename": {
            "count": len(filler),
            "note": "one side is reserved or padding, so the meaning changed "
                    "rather than the label; an alias here would mislead",
            "candidates": [filler[k] for k in sorted(filler)],
        },
    }


# ---------------------------------------------------------------------------
# Atom
# ---------------------------------------------------------------------------


def _label(version: str | None, kbs: list[str], key: str | None) -> str:
    """Name a build the way a reader can act on.

    Version first, then the KB. 79% of ARM64 builds carry no version string
    (4.5), and "KB5065789" is something a person can look up; the first ten
    characters of a PDB GUID are not.
    """
    if version:
        return version
    if kbs:
        return "/".join(kbs)
    return (key or "unknown")[:12]


def _summarise(change: dict) -> str:
    names = [t["type"] for t in change["types_changed"]]
    names += [e["enum"] for e in change.get("enums_changed", [])]
    if not names:
        return "layout hash changed with no visible difference"
    head = ", ".join(names[:4])
    return head + (f", and {len(names) - 4} more" if len(names) > 4 else "")


def _describe(change: dict) -> str:
    lines = []
    for entry in change["types_changed"]:
        if entry.get("status"):
            lines.append(f"{entry['type']}: {entry['status']}")
            continue
        parts = []
        if entry["size_from"] != entry["size_to"]:
            parts.append(f"size {entry['size_from']:#x} -> {entry['size_to']:#x}")
        for label, key in (("added", "members_added"), ("removed", "members_removed")):
            if entry[key]:
                parts.append(f"{label}: {', '.join(entry[key][:6])}"
                             + (" ..." if len(entry[key]) > 6 else ""))
        for label, key in (("moved", "members_moved"), ("resized", "members_resized"),
                           ("bitfields", "members_rebitted"), ("retyped", "members_retyped")):
            if entry[key]:
                parts.append(f"{label}: {len(entry[key])}")
        if entry["members_renamed"]:
            parts.append("renamed: " + ", ".join(
                f"{r['from']} -> {r['to']}" for r in entry["members_renamed"][:4]))
        lines.append(f"{entry['type']}: " + "; ".join(parts))

    for entry in change.get("enums_changed", []):
        if entry.get("status"):
            lines.append(f"{entry['enum']}: {entry['status']}")
            continue
        parts = []
        for label, key in (("added", "constants_added"),
                           ("removed", "constants_removed")):
            if entry[key]:
                parts.append(f"{label}: {', '.join(entry[key][:6])}")
        if entry["constants_renumbered"]:
            parts.append("renumbered: " + ", ".join(
                f"{c['name']} {c['from']}->{c['to']}"
                for c in entry["constants_renumbered"][:4]))
        lines.append(f"{entry['enum']}: " + "; ".join(parts))
    return "\n".join(lines)


def atom(feed: Feed, *, base_url: str, limit: int = 100) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        "<title>ntoffsets kernel layout changes</title>",
        f"<id>{FEED_ID}</id>",
        f"<updated>{generated}</updated>",
        f'<link rel="self" href="{escape(base_url)}/feed/changes.xml"/>',
        f'<link rel="alternate" href="{escape(base_url)}/"/>',
        "<subtitle>Which kernel structs moved, and in which update. "
        "No entries means nothing moved.</subtitle>",
    ]

    for change in feed.changes[:limit]:
        origin = _label(change["from_version"], change.get("from_kb", []),
                        change["from_key"])
        target = _label(change["to_version"], change["kb"], change["to_key"])
        title = (f"{change['channel']} {change['machine']} {origin} -> {target}: "
                 f"{_summarise(change)}")
        entry_id = f"{FEED_ID}:{change['from_key']}:{change['to_key']}"
        updated = f"{change['date']}T00:00:00Z" if change.get("date") else generated
        kb = ", ".join(change["kb"]) or "unknown KB"
        summary = (f"{len(change['types_changed'])} type(s) changed in {kb}"
                   f" ({change['channel']}, {change['machine']})")
        parts += [
            "<entry>",
            f"<title>{escape(title)}</title>",
            f"<id>{escape(entry_id)}</id>",
            f"<updated>{updated}</updated>",
            f'<link rel="alternate" href="{escape(base_url)}'
            f'/v1/build/{change["to_key"]}.json"/>',
            f"<summary>{escape(summary)}</summary>",
            f"<content type=\"text\">{escape(_describe(change))}</content>",
            "</entry>",
        ]

    parts.append("</feed>")
    return "\n".join(parts) + "\n"


def write(feed: Feed, feed_dir: Path, *, base_url: str) -> dict[str, Path]:
    feed_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    document = feed_document(feed)
    (feed_dir / "changes.json").write_text(json.dumps(document, indent=1), encoding="utf-8")
    written["changes.json"] = feed_dir / "changes.json"

    (feed_dir / "changes.xml").write_text(atom(feed, base_url=base_url), encoding="utf-8")
    written["changes.xml"] = feed_dir / "changes.xml"

    alias_path = feed_dir / "aliases.json"
    existing = json.loads(alias_path.read_text(encoding="utf-8")) if alias_path.exists() else None
    alias_path.write_text(
        json.dumps(aliases_document(existing, feed), indent=1), encoding="utf-8"
    )
    written["aliases.json"] = alias_path

    review = review_document(feed)
    (feed_dir / "renames-review.json").write_text(json.dumps(review, indent=1), encoding="utf-8")
    written["renames-review.json"] = feed_dir / "renames-review.json"

    return written
