"""Cross validation: our parser against Microsoft's own PDB reader.

This is the gate (15.2). A wrong offset does not raise an exception, it
produces a plausible number that later dereferences a kernel pointer at the
wrong address, and the report arrives as a bugcheck on someone else's machine.
The only defence is an independent second reading, and DIA is the strongest one
available: it is the implementation the format's authors ship.

Disagreements are always resolved in DIA's favour. If our parser and DIA differ,
our parser is wrong until proven otherwise.

    python -m ntoff gate
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


from . import config
from .model import Extraction, Member



@dataclass
class Report:
    checked_types: int = 0
    checked_members: int = 0
    checked_bitfields: int = 0
    checked_symbols: int = 0
    checked_enums: int = 0
    checked_constants: int = 0
    # A finding is (severity, type or symbol, description). Bitfield geometry
    # and byte offsets are fatal; a differing member *size* is worth knowing
    # about but does not by itself put a caller at a wrong address.
    fatal: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.fatal


def _by_name(members: list[Member]) -> dict[str, Member]:
    return {m.name: m for m in members}


def compare(oracle: Extraction, subject: Extraction, type_names: list[str]) -> Report:
    report = Report()

    for type_name in type_names:
        golden = oracle.types.get(type_name)
        ours = subject.types.get(type_name)

        if golden is None:
            # The subject produced a type the oracle has no record of. That is
            # not a build difference -- both read the same PDB -- so it is the
            # subject inventing something, and skipping it left a hole the
            # `<unnamed-tag>` chimera walked straight through.
            if ours is not None:
                report.fatal.append(
                    (type_name, f"type absent from dia (subject has {len(ours.members)} members)")
                )
            continue
        if ours is None:
            report.fatal.append((type_name, "absent from rust-pdb output"))
            continue

        report.checked_types += 1

        if golden.size != ours.size:
            report.fatal.append(
                (type_name, f"size {ours.size:#x} != dia {golden.size:#x}")
            )

        golden_members = _by_name(golden.members)
        our_members = _by_name(ours.members)

        for name in sorted(set(golden_members) - set(our_members)):
            member = golden_members[name]
            report.fatal.append(
                (type_name, f"member {name!r} missing (dia: offset {member.offset:#x})")
            )
        for name in sorted(set(our_members) - set(golden_members)):
            member = our_members[name]
            report.fatal.append(
                (type_name, f"member {name!r} invented (offset {member.offset:#x})")
            )

        for name in sorted(set(golden_members) & set(our_members)):
            want, got = golden_members[name], our_members[name]
            report.checked_members += 1
            if want.is_bitfield or got.is_bitfield:
                report.checked_bitfields += 1

            if want.offset != got.offset:
                report.fatal.append(
                    (type_name, f"{name}: offset {got.offset:#x} != dia {want.offset:#x}")
                )
            # An empty type on either side is a reader that could not
            # resolve the record, not a disagreement about what the record
            # says. Reporting it as a mismatch would blame the parser for a
            # gap in whichever renderer stopped first.
            if want.type and got.type and want.type != got.type:
                report.fatal.append(
                    (type_name, f"{name}: type {got.type!r} != dia {want.type!r}")
                )
            if (want.bit_position, want.bit_count) != (got.bit_position, got.bit_count):
                report.fatal.append(
                    (
                        type_name,
                        f"{name}: bits {got.bit_position}:{got.bit_count} "
                        f"!= dia {want.bit_position}:{want.bit_count}",
                    )
                )
            if want.size != got.size:
                report.warnings.append(
                    (type_name, f"{name}: size {got.size} != dia {want.size}")
                )

    for name in sorted(set(oracle.enums) | set(subject.enums)):
        golden = oracle.enums.get(name)
        ours = subject.enums.get(name)
        if golden is None:
            report.fatal.append((name, "enum invented by rust-pdb"))
            continue
        if ours is None:
            report.fatal.append((name, "enum absent from rust-pdb output"))
            continue

        report.checked_enums += 1
        if golden.size != ours.size:
            report.fatal.append((name, f"enum size {ours.size} != dia {golden.size}"))

        want = {c.name: c.value for c in golden.constants}
        got = {c.name: c.value for c in ours.constants}
        for constant in sorted(set(want) - set(got)):
            report.fatal.append((name, f"constant {constant!r} missing"))
        for constant in sorted(set(got) - set(want)):
            report.fatal.append((name, f"constant {constant!r} invented"))
        for constant in sorted(set(want) & set(got)):
            report.checked_constants += 1
            if want[constant] != got[constant]:
                report.fatal.append(
                    (name, f"{constant} = {got[constant]} != dia {want[constant]}")
                )

    for name, rva in sorted(oracle.rvas.items()):
        ours = subject.rvas.get(name)
        report.checked_symbols += 1
        if ours is None:
            report.fatal.append((name, "symbol missing from rust-pdb output"))
        elif ours != rva:
            report.fatal.append((name, f"rva {ours:#x} != dia {rva:#x}"))

    return report
