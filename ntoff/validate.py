"""Self-consistency and continuity checks (13.1, 13.4).

The DIA cross-check is the strongest signal we have, and it cannot run where
the pipeline actually runs: DIA is Windows-only COM and the extraction happens
on Linux runners (3). Everything here works on the extractor's own output, so
it can gate every CI run rather than only the ones done at a Windows desk.

These checks are weaker than the oracle by construction. They cannot tell a
right offset from a wrong one. What they catch is a parser that has gone
incoherent -- a member past the end of its struct, a bitfield wider than the
word holding it, a type whose size collapsed to zero because a forward
reference was never resolved -- and every one of those has been a real bug in
a PDB reader at some point.

    python -m ntoff validate
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


from .model import Extraction, TypeLayout


# A bitfield lives inside one storage unit; anything else means the underlying
# type was misread.
VALID_STORAGE_SIZES = {1, 2, 4, 8}

# 13.4: how far a member may move between adjacent builds *beyond* what the
# struct's own size change already explains.
#
# The first version compared the raw movement against this alone, which was
# right for 37 curated types and useless for 1,646: inserting a field near the
# front of `_EX_POOL_HEAP_MANAGER_STATE` shifts everything after it, and the
# check fired 4,247 times on 1,967 builds. 94% of those moves matched the
# struct's growth almost exactly -- `SpecialHeaps` moved 0x83080 in a struct
# that grew 0x830C0 -- which is not a finding, it is arithmetic.
#
# Subtracting the size change first leaves 257, and what remains is members
# that moved *within* a struct rather than being pushed along by it. That is
# the shape a parser fault has, and it is also the shape a real reordering has,
# which is why it is a warning and not an error.
CONTINUITY_LIMIT = 0x1000

MACHINE = {0x8664: "amd64", 0xAA64: "arm64", 0x014C: "x86"}


@dataclass
class Findings:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def check_self_consistency(extraction: Extraction) -> Findings:
    findings = Findings()

    for name, layout in sorted(extraction.types.items()):
        if layout.size == 0:
            findings.errors.append(f"{name}: size is zero (unresolved forward reference?)")
            continue
        if not layout.members:
            findings.errors.append(f"{name}: no members")
            continue

        last_offset = max(m.offset for m in layout.members)
        for member in layout.members:
            where = f"{name}.{member.name}"

            if member.offset + member.size > layout.size:
                findings.errors.append(
                    f"{where}: ends at {member.offset + member.size:#x}, "
                    f"past the {layout.size:#x} byte struct"
                )
            if member.size == 0 and member.offset != last_offset:
                # A zero-sized member at the end is the flexible-array idiom
                # (`Elements[]`), which is correct and extremely common. One
                # anywhere else means a type resolved to nothing, which is the
                # forward-reference bug wearing a different hat.
                findings.warnings.append(f"{where}: zero sized, not the last member")

            if member.is_bitfield:
                if member.size not in VALID_STORAGE_SIZES:
                    findings.errors.append(
                        f"{where}: bitfield in a {member.size} byte storage unit"
                    )
                elif member.bit_position + member.bit_count > member.size * 8:
                    findings.errors.append(
                        f"{where}: bits {member.bit_position}:{member.bit_count} "
                        f"overflow a {member.size} byte unit"
                    )
            elif member.bit_position or member.bit_count:
                findings.errors.append(
                    f"{where}: bit geometry on a non-bitfield member"
                )

        _check_overlaps(name, layout, findings)

    for name, enum in sorted(extraction.enums.items()):
        if not enum.constants:
            findings.warnings.append(f"{name}: enumeration with no constants")
            continue
        if enum.size not in VALID_STORAGE_SIZES:
            findings.errors.append(f"{name}: enum size {enum.size}")

        seen: dict[str, int] = {}
        for constant in enum.constants:
            if constant.name in seen and seen[constant.name] != constant.value:
                findings.errors.append(
                    f"{name}.{constant.name}: two values, "
                    f"{seen[constant.name]} and {constant.value}"
                )
            seen[constant.name] = constant.value
            # A constant wider than its own storage means the numeric leaf was
            # read against the wrong type -- the failure mode that turned -1
            # into 255 the first time enums were extracted.
            bits = enum.size * 8
            if bits < 64 and not (-(1 << (bits - 1)) <= constant.value < (1 << bits)):
                findings.errors.append(
                    f"{name}.{constant.name} = {constant.value} does not fit "
                    f"{enum.size} byte(s)"
                )

    return findings


def _check_overlaps(name: str, layout: TypeLayout, findings: Findings) -> None:
    """Two members may share bytes only if they share a union (13.1).

    Members flattened out of the same anonymous union are supposed to overlap;
    that is what a union is. Anything else means the parser placed a member
    where it does not belong, which is the failure mode this whole file exists
    to catch.

    Telling the two apart needs `union_group`, which only the Rust extractor
    emits. Against DIA output the check is skipped rather than guessed at: a
    check that cannot distinguish right from wrong should not render a verdict.
    """
    if not any(member.union_group for member in layout.members):
        return

    plain = sorted(m for m in layout.members if not m.is_bitfield and m.size)
    for index, earlier in enumerate(plain):
        end = earlier.offset + earlier.size
        for later in plain[index + 1 :]:
            if later.offset >= end:
                break
            if earlier.union_group and earlier.union_group == later.union_group:
                continue
            findings.errors.append(
                f"{name}: {earlier.name} [{earlier.offset:#x},{end:#x}) overlaps "
                f"{later.name} at {later.offset:#x} with no shared union"
            )


def check_continuity(previous: Extraction, current: Extraction, label: str) -> Findings:
    """Compare adjacent builds and flag movement the size change cannot explain.

    Reported once per type, not once per member. A reordering inside a large
    struct moves hundreds of members at once, and hundreds of lines saying the
    same thing is how a check stops being read.
    """
    findings = Findings()

    for name, layout in sorted(current.types.items()):
        before = previous.types.get(name)
        if before is None:
            continue

        grew = abs(layout.size - before.size)
        old_offsets = {m.name: m.offset for m in before.members}

        worst = 0
        worst_member = ""
        moved = 0
        for member in layout.members:
            old = old_offsets.get(member.name)
            if old is None:
                continue
            distance = abs(member.offset - old)
            if distance > grew + CONTINUITY_LIMIT:
                moved += 1
                if distance > worst:
                    worst, worst_member = distance, member.name

        if moved:
            findings.warnings.append(
                f"{label} {name}: {moved} member(s) moved further than the "
                f"{grew:#x} byte size change explains, worst "
                f"{worst_member} by {worst:#x}"
            )

    return findings


def _version_key(version: str) -> tuple[int, ...]:
    parts = [int(p) for p in version.split(".") if p.isdigit()]
    return tuple(parts + [0] * (4 - len(parts)))[:4]
