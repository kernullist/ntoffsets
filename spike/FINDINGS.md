# Spike results

Against the four items in design 15.2. Run 2026-09-02.

**The gate passed.** The Rust `pdb` crate agrees with DIA exactly, on every
type, member, bitfield, enum constant and symbol, across **1,967 builds** —
1,210 amd64, 738 ARM64 and 19 x86, spanning 1507 (2015) to 26H1 (2026). No
fallback to DIA-in-CI is needed and the project's central assumption holds.

That figure is the whole database, not a sample: 91.3% of every `ntoskrnl.exe`
the three Winbindex datasets know about. The rest is absent upstream.

---

## 1. Acquisition (2 h budget) — pass

Winbindex's `ntoskrnl.exe` index has **1136 entries**, all amd64.

**Finding not in the design: the index publishes no PDB GUIDs at all.** 4.4
allowed for entries with and without them and expected to skip the binary
fetch where one was present. There are none, so every build goes through the
binary route. That would have been the expensive path — a kernel is 8–14 MB —
except that msdl's storage honours HTTP ranges:

| | per build |
|---|---|
| Whole binary | 8–14 MB |
| **Ranged read of the CodeView record** | **48 KiB, 3 requests** |

A 270x reduction on the leg that touches every build. `ntpe.py` is written
against a `read(offset, size)` callable for this reason; the local-file and
over-the-network paths are the same code.

Resolution rate: **71 of 73** attempted. Both failures were `404` on the
binary, which 4.2 already classifies as coverage data rather than error.

**Also not in the design: Winbindex is three datasets, split by architecture
as well as channel.** The site serves x86 and amd64 only — 8 files and 5,346
entries checked, zero ARM64. ARM64 lives in `winbindex-data-arm64` on its own
`gh-pages` branch, unlinked from the site: 681 `ntoskrnl.exe` entries, all
machine type 0xAA64, 1709 through 11-26H1. Insider is a third repository.

Worth recording how this was nearly missed. The first conclusion here was "no
ARM64 input source exists, drop it from the roadmap." The observation was
right and the conclusion was wrong, because only one endpoint had been checked.
A project whose differentiator is saying what it does not have needs the same
discipline pointed at its own research: *not visible at one endpoint* is not
*does not exist*.

ARM64 metadata is thinner, and it changes what can be offered:

| | entries | no `version` | not downloadable |
|---|---|---|---|
| GA (amd64) | 1136 | 18 (1.6%) | 2 |
| **ARM64** | 681 | **541 (79%)** | 30 |

Lookups are unaffected — the key is the PDB GUID, not the version string — but
the human-readable `resolve?version=` path will be mostly empty for ARM64, and
`by-version.json` will be sparse there by nature rather than by bug.

## 2. Bitfield accuracy (3 h budget) — **PASS, and this was the gate**

Instead of reading WinDbg `dt -v -b` by eye, the oracle is `msdia140.dll`
driven directly over registration-free COM. Same authority, mechanically
comparable, and it scales past the handful of types a person can check.

| arch | builds | types | members | bitfields | symbols | mismatches |
|---|---|---|---|---|---|---|
| amd64 | 70 | 37 each | ~1,600–1,800 | ~370–395 | 16 each | **0** |
| ARM64 | 55 | 37 each | ~1,390–1,650 | ~320–385 | 16 each | **0** |

amd64 spans 1809, 1903, 1909, 2004, 20H2, 21H2, 22H2, 11-21H2, 11-22H2,
11-23H2, 11-24H2 (all 58 consecutive builds), 11-25H2, 11-26H1. ARM64 spans
1709, 1903, 2004, 21H2, 22H2, 11-21H2, 11-22H2, and 11-24H2 (48 consecutive).

**ARM64 needed no parser changes at all.** CodeView is architecture neutral;
the only place the extractor assumes an architecture is the primitive size
table's "every indirection is eight bytes", and that holds on ARM64 too. The
layouts themselves are entirely different — `_EPROCESS` is `0x840` on amd64
and `0xc80` on ARM64 for the same 22621 build — which is what makes the
agreement meaningful rather than trivial. x86 is where that assumption would
finally break, so it gets parameterised if and when x86 is taken on.

### The bug it caught

The first gate run failed with 100 mismatches on `_EPROCESS` alone. MSVC names
the type of every anonymous aggregate `<unnamed-type-X>`, in two situations
that look identical and are not:

```c
union {
    ULONG MitigationFlags;
    struct { ULONG ControlFlowGuardEnabled : 1; ... } MitigationFlagsValues;
    //                                               ^ named member: opaque
};
union {
    ULONG Flags2;
    struct { ULONG JobNotReallyActive : 1; ... };
    //                                     ^ unnamed member: transparent
};
```

Deciding on the **type** name flattened both. That invented 96 `_EPROCESS`
members at offsets where no such member exists, and dropped the 4 that do —
silently, in both directions, with every offset still looking plausible. The
correct test is on the **member** name.

This is precisely the failure mode 2.5 warns about and 15.2 built the gate for.
A parser can be wrong in a way that produces no error, no exception and no
implausible number. Nothing but a second independent reading finds it.

## 3. Content addressing (2 h budget) — validated

Measured the way M2 requires: one channel, every consecutive build, not a
random sample across a decade.

**11-24H2 amd64: 58 builds → 8 distinct layouts.** 7.25:1. The same channel on
ARM64 gives 48 builds → 8 layouts, so content addressing is not an
architecture-specific effect.

| layout | builds | range |
|---|---|---|
| `1949e48beb6b` | 13 | 26100.8115 – 26100.9278 |
| `3a1746791388` | 11 | 26100.1 – 26100.2314 |
| `d5df7e126455` | 10 | 26100.3624 – 26100.4656 |
| `ce56d535ca21` | 8 | 26100.7309 – 26100.8036 |
| `09bcffde9c53` | 5 | 26100.6725 – 26100.7171 |
| `b138e73b8ffe` | 4 | 26100.4768 – 26100.6584 |
| `f89cfe49d309` | 4 | 26100.3037 – 26100.3476 |
| `a65025724a8d` | 3 | 26100.2454 – 26100.2894 |

Layouts hold for 3 to 13 consecutive builds and then move as a block. Comfortably
inside 15.2's "3–6 kinds good, 12 still fine" band, and it confirms 8.4's point
that the real benefit is operational: 50 of 58 builds produce no new layout file
at all, so most days there is nothing to commit.

For contrast, the stratified sample — one build per channel, deliberately
maximising diversity — gives 11 layouts across 14 builds. That is the number M2
predicted a random sample would produce, and it is the wrong measurement.

## 4. Backfill cost (1 h budget) — well inside budget

Measured: PDBs average **10.5 MiB** (7.2–12.3), 70 cached.

| scope | builds | GUID discovery | PDB download |
|---|---|---|---|
| P0 tier (4.3) | 191 | 9 MiB, ~10 min | 2.0 GiB |
| Whole index | 1136 | 53 MiB, ~55 min | 11.6 GiB |

Times assume the serialized, 1-second-spaced client in `msdl.py`. **P0 finishes
in well under a day**, against 15.2's three-day threshold, so 4.3's tiers do not
need subdividing.

These numbers were first computed at 253 builds, because the implementation had
quietly put `11-21H2` in P0. The design tier is "11-22H2 onward plus 10-22H2
LTSC", which is 191. The tiers exist to hold the request count down; widening
the first one by a third for an out-of-support channel is exactly how that
erodes.

No throttling was observed at this volume. That is not evidence it is absent —
4.3's caution stands, and the politeness measures stay.

---

## Rename detection: the premise did not survive contact

10.2 assumed the common case would be a label change — `MitigationFlags` to
`MitigationFlags2` — and that aliasing both names would spare every consumer a
build check. Across the first 237 builds and 225 transitions, the heuristic
found 13 candidates, 7 unique, and **none of them were renames** — a conclusion
that turned out to be an artefact of extracting only 37 curated types. With all
1,646, the same pipeline finds 367 genuine renames alongside 200 of the
repurposings below.

| type | from | to | what actually happened |
|---|---|---|---|
| `_KPRCB` | `BpbStateReserved` | `BpbDivideOnReturn` | reserved bit became a mitigation flag |
| `_KPRCB` | `PrcbPad139c` | `RawRelativePerformance` | padding became a field |
| `_KPRCB` | `PrcbPad12` | `PrcbPad12c` | padding stayed padding |
| `_EPROCESS` | `ProcessExecutionState` | `Flags2Available1` | field was **retired** |
| `_EPROCESS` | `NumberOfLockedPages` | `MmReserved2` | field became reserved |
| `_ETHREAD` | `UpdateTebSpareLong2` | `HeapData` | spare became a field |
| `_KAPC` | `SpareByte0` | `AllFlags` | spare became a field |

What Microsoft does is consume padding and retire fields, not relabel them. An
alias on any of these would be actively harmful: a caller asking for
`ProcessExecutionState` and getting `Flags2Available1`'s bytes reads a correct
offset holding a value that stopped meaning anything — a silent wrong answer,
which is the failure mode this project is built to avoid.

So renames are now classified before being aliased, and only `rename` (neither
side reserved or padding) produces one. Where the classifier is unsure it calls
the name filler: a missing alias costs a consumer one build check, a wrong one
costs them correctness.

`aliases.json` is consequently empty. That is the honest output, and the
feature still earns its place — it caught seven changes that look like renames
if you only compare offsets, and said so.

## Final coverage

| | builds | share |
|---|---|---|
| Known (distinct, across three datasets) | 2,154 | |
| **Resolved** | **1,967** | **91.3%** |
| `binary_404` — no binary on the symbol server | 175 | 8.1% |
| `pdb_404` — binary present, no PDB | 11 | **0.5%** |
| `undownloadable` — no URL derivable at all | 1 | |
| Defects (ours) | 0 | |

**`pdb_404` at half a percent is the surprise.** The expectation was that older
builds would have unpublished symbols; the opposite holds. For `ntoskrnl.exe`,
if the binary reached the symbol server the PDB almost always did too. What is
missing is missing because the *binary* is gone.

Nor is age the factor. 1511 and 1703 are at 100%, 1507 and 1607 at 98%. The
gaps concentrate in **Insider (60%)**, which holds 90 of the 187 — builds being
withdrawn is what that channel is for.

## Carried forward

- **ARM64 is available and works.** Source found, gate passed, no code changes. It stays
  second priority for demand reasons, not capability ones. The collector takes the dataset
  as a parameter.
- **No GUIDs in the Winbindex index**, so the binary route is universal, not a fallback. 4.4 should say so.
- **Union grouping is Rust-only.** DIA's flattened view reports every member's parent
  as the outer type, losing the union entirely, so it cannot supply the grouping that
  makes 13.1's overlap check sound. The Rust extractor emits `union_group`; it is kept
  out of the layout hash and out of the oracle comparison, since it is derived structure
  rather than layout. With it, 58 builds report **0 overlap errors**.
- **Continuity check works.** Its one warning across 58 builds — `_KPRCB.NodeRelativeTopologyIndex`
  moving 0x8e2c → 0xb928 at 26100.7309 — is a real change: same struct size, six new members,
  a field relocated into padding. A true positive, not a false one.
- **Not yet done:** a third reading via `dbghelp`. `dbh.exe` loads a PDB standalone but will
  not enumerate type children, so this needs `SymGetTypeInfo` over ctypes. DIA already
  settles the questions that matter most, so this is confirmation rather than a gap.
