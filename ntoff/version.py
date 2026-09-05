"""What a Windows version string means for ordering and grouping.

This exists because the answer was written three times. `version_key` was
byte-identical in `diff` and `winbindex`, plus a dead third copy in `validate`,
and `sequences` and the continuity check each had their own idea of which
builds sit next to each other. Copies agree until one of them is fixed; the
Insider grouping bug survived its own fix in a second copy for exactly that
reason. One home, so the next correction lands everywhere.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def sort_key(version: str | None) -> tuple[int, ...]:
    """Order `10.0.26100.4652` numerically, not as text.

    Padded to four parts so a two-part version sorts below a four-part one
    sharing its prefix, and truncated there because nothing downstream orders
    on a fifth.
    """
    parts = [int(part) for part in (version or "").split(".") if part.isdigit()]
    return tuple(parts + [0] * (4 - len(parts)))[:4]


def family(version: str | None) -> str | None:
    """The Windows build number a version belongs to: 10.0.**26100**.4652.

    `None` when the version is missing or malformed. That is not the same as
    "unknown family" and callers must not merge those cases -- 79% of the ARM64
    index has no version string at all (4.5), and pretending they share a
    lineage would invent adjacency.
    """
    parts = (version or "").split(".")
    return parts[2] if len(parts) >= 3 and parts[2].isdigit() else None


def mixed_channels(entries: Iterable[tuple[Iterable[str], str | None]]) -> set[str]:
    """Channel names that cover more than one Windows version.

    A GA channel name pins a version -- 11-24H2 is 26100 and nothing else -- so
    the label alone is a safe grouping key there. The Insider dataset files
    every build it lists under a single channel named `builds`, spanning 19041
    to 28000, and treating that as one run makes 19041 and 22621 neighbours.

    `entries` is (channels, version) pairs, so this works on stored builds and
    on unresolved candidates alike. Nothing keys off a dataset name: this is
    not a property of Insider, it is what happens when a label is trusted to
    name one lineage and does not.
    """
    seen: dict[str, set[str]] = defaultdict(set)
    for channels, version in entries:
        found = family(version)
        if found:
            for channel in channels:
                seen[channel].add(found)
    return {channel for channel, families in seen.items() if len(families) > 1}


def channel_label(channel: str, version: str | None, mixed: set[str]) -> str | None:
    """The grouping key for one build in one channel.

    `None` means the build cannot be placed: its channel holds several versions
    and it has no version string of its own. Insider rings ship different
    Windows versions in the same week, so the release date cannot stand in, and
    a neighbour we cannot establish is worse than one we do not claim.
    """
    if channel not in mixed:
        return channel
    found = family(version)
    return f"{channel}/{found}" if found else None
