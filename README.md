# ntoffsets

**Winbindex finds the file. ntoffsets finds the numbers inside it.**

A public database of Windows kernel struct layouts and global symbol RVAs, per
build, collected in CI without owning a single machine.

```
  Question:  "where is _EPROCESS.Token on build 26100.4351?"

  +---------------------------------------------------------------+
  |  ntoffsets        symbol meaning                               |
  |                   struct layouts, global symbol RVAs, diffs    |
  +---------------------------------------------------------------+
                      | consumes
  +---------------------------------------------------------------+
  |  Winbindex        file identity                                |
  |                   which versions exist, where to get them      |
  +---------------------------------------------------------------+
                      | consumes
  +---------------------------------------------------------------+
  |  msdl             original distribution                        |
  |                   the PE and PDB themselves                    |
  +---------------------------------------------------------------+
```

## Credit

**This project does not exist without [Winbindex](https://winbindex.m417z.com)
by [m417z](https://github.com/m417z).** The obstacle here was never parsing —
it was obtaining kernel binaries for thousands of builds without thousands of
machines. Winbindex's metadata index removes that obstacle entirely. Winbindex
stops at "this file exists and here is where to get it"; ntoffsets starts
exactly there.

Symbols come from the [Microsoft Public Symbol
Server](https://msdl.microsoft.com). We redistribute neither PDBs nor binaries —
only offsets derived from them.

We also try not to be a burden: the Winbindex snapshot is downloaded whole and
queried locally rather than crawled, at most once a day. Binary reads against
msdl use HTTP ranges and take about 48 KiB per build instead of the 8–14 MB a
whole kernel would cost.

## Status

Backfilled: **1,967 of 2,154 known builds (91.3%)** — 1,210 amd64, 738 ARM64,
19 x86, spanning 1507 through 26H1. 517 distinct layouts, 6,738 type bodies,
25,223 global symbol names, **zero mismatches against DIA**.

The 187 that are missing are missing upstream: 175 have no binary on the symbol
server and 11 have a binary but no PDB. Nothing is missing because of us. See
[`spike/FINDINGS.md`](spike/FINDINGS.md).

The design document is not published yet.

## The gate

The largest risk in this project is not legal exposure or hosting limits — it
is a parser that is quietly wrong. A bad offset does not raise an exception; it
produces a plausible number that dereferences a kernel pointer at the wrong
address, and the bug report arrives as a bugcheck on someone else's machine.

So every layout is read twice, by two independent implementations, and the
results must match exactly:

| | |
|---|---|
| `crates/ntoff-extract` | Rust, the `pdb` crate. Ships. Runs on a Linux CI runner. |
| `ntoff/dia.py` | Microsoft's own `msdia140.dll`, via registration-free COM. The oracle. Windows only, never ships. |

DIA wins every disagreement, and it has earned that standing several times over:

- `<unnamed-type-Foo>` is the type name MSVC gives an anonymous aggregate, and it
  appears both where the member is anonymous (flatten it) and where the member is
  named (do not). Keying off the type name invented 96 `_EPROCESS` members that do
  not exist and dropped 4 that do — silently, in both directions.
- `LF_CHAR` is a *signed* CodeView leaf that the `pdb` crate hands back unsigned, so
  `ArbiterRequestUndefined` read as 255 instead of -1. Code comparing against a
  sentinel would simply never match.
- `PVOID64` is a 64-bit pointer on x86. Sizing pointers by the target machine —
  itself a fix for having hardcoded eight — got `_FILE_SEGMENT_ELEMENT.Buffer` wrong
  in the other direction.

The comparison covers the **union** of what both readers found, not just the
oracle's list. It did not always: a type the parser invented was never examined,
and that hole let a chimeric `<unnamed-tag>` through three passing gates.

```bash
python -m ntoff gate --local
```

```bash
python -m ntoff validate
```

## Keeping up with Windows

```
.github/workflows/collect.yml   daily: collect, validate, feed, publish
.github/workflows/gate.yml      weekly on Windows: cross-check against DIA
.github/workflows/verify.yml    weekly: re-derive published values from msdl
```

Windows ships around 14 dated kernel builds a month, and `collect` resumes, so
most days the run makes no requests at all and writes nothing. The gate is a
separate workflow because DIA is Windows-only COM while the pipeline runs on
Linux — which is why the self-consistency and continuity checks were built to
run without DIA: those can block every collection, the oracle gates releases.

`verify` deliberately checks out no store. It has what a stranger has: the
public URLs and Microsoft's symbol server.

CI never passes `--force`. Re-extracting everything needs the local PDB cache;
without one it would re-download 1,967 PDBs from msdl, which is exactly the
traffic the throttling rules exist to prevent. A schema change is a local
operation.

## Running your own copy

The pipeline needs no machine and no licence, but it does need somewhere to
keep its state. Two repositories: this one holds the code and serves the site,
and `<owner>/ntoffsets-data` holds the store on a `store` branch and the
published data on `gh-pages`. Both must be public — Pages on a private
repository needs a paid plan, and the data origin has to answer cross-origin
requests from the site.

    gh repo create ntoffsets-data --public

    # gh-pages has to exist before the first run: actions/checkout fails on a
    # branch that is not there. The content arrives on the first run.
    git init -q -b gh-pages && touch .nojekyll && git add -A
    git commit -qm "bootstrap" && git push https://github.com/<owner>/ntoffsets-data gh-pages

    # Push a store you already have. Starting from an empty one makes the first
    # run fetch 1,967 PDBs from msdl, which is the traffic to avoid.
    cd data && git init -q -b store && git add -A && git commit -qm store
    git remote add origin https://github.com/<owner>/ntoffsets-data.git
    git push -u origin store

`collect` pushes to the other repository, so it needs a token the default
`GITHUB_TOKEN` cannot replace: a fine-grained PAT with Contents: read and write
on `ntoffsets-data`, stored on *this* repository as `NTOFF_DATA_TOKEN`. Then
enable Pages on both, `gh-pages` at the root.

One caveat worth knowing: a repository created and pushed in the same breath
can land its workflow files while Actions is still being provisioned, and they
are then never indexed. Any later push to the default branch fixes it.

## Licence

The software is Apache-2.0 (`LICENSE`). The data — offsets, type layouts, enum
constants, symbol addresses — is CC0 (`LICENSE-DATA`): public domain, no
attribution required, no conditions.

The split is deliberate. The numbers are measurements of Microsoft's binaries,
not authorship, and a copyright claim over `0x248` is not one we think we have.
Embed them in whatever you like.

We redistribute neither PDBs nor binaries. Every value here is derived from
files Microsoft serves from its own symbol server.

## Checking it yourself

```bash
python -m ntoff verify --source https://<host>/ --sample 30
```

`verify` re-fetches each PDB from Microsoft, extracts it again, and compares
against what is **published** — not against our working copy, which would only
show the store agrees with itself. It recomputes the content hash rather than
trusting the filename, so a layout filed under the wrong name fails just as a
layout whose bytes do not match its name does. Symbol bitmaps are decoded and
compared as name-to-address pairs, because the encoding is positional and one
wrong bit shifts everything after it.

Tampering with a published offset, an RVA, a manifest entry or a single bitmap
bit each makes it fail. `--seed` fixes the sample so a published result can be
reproduced by anyone.

Against a URL, fetching every type body costs ~1,700 requests per build, so
`--bodies` (40 by default remotely, all of them locally) samples them and the
output says how many it actually fetched. The sample is chosen by hashing the
build key with each type name, so it spreads across the manifest and anyone
holding the key can recompute which bodies a published run looked at.

## Every page says which build

The header carries the build in context on every page — version, architecture,
channel, release date — and the type pages resolve against it. `_KPROCESS` is
456 bytes in 10.0.28000.2804 and 728 in 10.0.14393.9418; change the build in
the header and the table changes with it. A type the selected build does not
have says so before falling back to the newest build that does, because a
quiet fallback is how a reader ends up using another build's numbers.

## Members carry their type

```
0x0     Pcb              _KPROCESS
0x1C8   ProcessLock      _EX_PUSH_LOCK
0x1D0   UniqueProcessId  void *
0x248   Token            _EX_FAST_REF
0x2E0   Peb              _PEB *
0x338   ImageFileName    unsigned char[15]
```

An offset and a size say where a member is and how wide. They do not say how
to read it, and `_EX_FAST_REF`, `PVOID` and `_LIST_ENTRY *` are all eight
bytes. The type is part of the layout contract, so it is in the hash — which
is why the layout schema is 2.

The spelling is a contract too, not whatever each library happens to print:
builtins use their C names, pointers are `T *`, arrays carry the element count,
`const`/`volatile` attach to whichever half they qualify (`T * volatile` is a
volatile pointer and `volatile T *` is not), and anything unresolvable is left
empty rather than guessed. The Rust reader and the DIA oracle render the same
records independently and are diffed against each other; the first run found
two real bugs, one on each side.

## What is in it

1,967 builds, 517 distinct layouts, 2,505 type and enum names. The number that
matters is how many distinct definitions each name has:

```
_KPRCB              119
_EPROCESS            70
PO_MEMORY_IMAGE      68
_ETHREAD             38
```

119 definitions of `_KPRCB` across the builds we hold. That is the short answer
to why picking offsets by version number breaks.

## Previewing the site

```bash
python -m ntoff site --data-out site-data --data-base http://127.0.0.1:8018
python -m ntoff serve
```

The output splits by how often a file changes rather than by channel: the site,
indexes and feed are rewritten every run and come to a couple of megabytes,
while the addressed data is immutable once written and is almost all of the
bytes. The page finds the data through `v1/config.json`, so moving it later
does not touch the page code.

`serve` exists because `python -m http.server` cannot preview that. Once the
data has its own origin every fetch for it is cross-origin, and the data host
has to send `Access-Control-Allow-Origin` — GitHub Pages sends it on
everything, object storage generally does not until told to.

## Usage

```bash
python -m ntoff collect --dataset ga --channel 11-24H2
```

`collect` runs the whole pipeline: enumerate from Winbindex, read each build's
PDB GUID over HTTP ranges, fetch symbols, extract, cross-check against DIA, and
write the content-addressed store. Nothing reaches the store that the oracle
disagreed with, or that failed its own consistency checks.

```bash
python -m ntoff feed
```

`feed` answers the question this project exists to answer: **did this month's
update move anything your driver depends on?** Most months it did not, and
that is the useful answer — wire it into CI and patch Tuesday is either green
or it names the types to retest.

```bash
python -m ntoff status
```

## Layout

```
types.toml                curated extraction allowlist
crates/ntoff-extract/     the shipping parser (Rust)
ntoff/winbindex.py        snapshot -> candidates -> PDB keys, three datasets
ntoff/msdl.py             symbol server client: ranged reads, cache, backoff
ntoff/ntpe.py             PE -> PDB GUID+Age over a random-access reader
ntoff/extract.py          drives the Rust extractor
ntoff/dia.py              the DIA oracle (Windows only, never ships)
ntoff/compare.py          the oracle diff
ntoff/validate.py         self-consistency and continuity (13.1, 13.4)
ntoff/store.py            content-addressed store
ntoff/coverage.py         what is missing and why
ntoff/verify.py           re-derive published values from Microsoft's PDBs
ntoff/version.py          how a Windows version string orders and groups
ntoff/site.py             assemble the static site; split site from data
ntoff/serve.py            preview it, split origins and CORS included
ntoff/cli.py              collect / census / gate / validate / verify / feed / site / serve
spike/FINDINGS.md         what the spike measured

data/
  layouts/v1/<sha256>.json    one file per distinct layout
  builds/<guid><age>.json     layout reference + global symbol RVAs
  index/by-version.json       version -> build keys
  index/coverage.json         gaps, with reasons
  index/unresolved.json       per-build record of every gap
  feed/changes.json           what moved between consecutive builds
  feed/changes.xml            the same, as Atom
  feed/aliases.json           confirmed member renames
  feed/renames-review.json    rename candidates a human has to settle
```

The store is regenerated by the pipeline, so it is not committed.

## Content addressing

Most builds do not change any struct layout, so most builds write no new
layout file. On 11-24H2 that is 58 consecutive amd64 builds sharing 8 layouts,
and 48 ARM64 builds sharing 8. The bytes saved matter less than the fact that
most days produce nothing to commit at all.

## The diff feed

Comparing consecutive builds within one channel and one architecture — both
axes matter, and getting either wrong turns the output into noise — gives the
one thing a file-identity layer cannot produce: not "a new kernel shipped" but
"`_EPROCESS` grew two members in KB5070311, and `_KPRCB` moved sixteen".

It also detects renames. A member that changes name is otherwise one removal
plus one addition, and a caller hashing the old name gets `STATUS_NOT_FOUND`
with nothing to explain it. When exactly one member disappears and exactly one
appears at the identical offset, size and bit geometry, that is a rename and it
goes into `aliases.json`. When two disappear and two appear, there is no way to
tell which became which, so it goes to a review file instead. Being unable to
answer is fine; answering wrongly puts a caller at the wrong offset.

Except that in 225 transitions, not one of the candidates was a rename.
Microsoft consumes padding and retires fields; it does not relabel them:

```
_KPRCB.BpbStateReserved       -> BpbDivideOnReturn   reserved bit -> mitigation flag
_KPRCB.PrcbPad139c            -> RawRelativePerformance
_EPROCESS.ProcessExecutionState -> Flags2Available1   field retired
_EPROCESS.NumberOfLockedPages -> MmReserved2
_ETHREAD.UpdateTebSpareLong2  -> HeapData
```

Aliasing any of those would be worse than useless. A caller asking for
`ProcessExecutionState` and getting `Flags2Available1`'s bytes reads a correct
offset holding a value that stopped meaning anything. So candidates are
classified first, and only a genuine label change becomes an alias; where the
classifier is unsure it errs toward *not* aliasing. `aliases.json` is empty,
which is the honest answer — and the feature still earned its keep by naming
seven changes that look like renames if you only compare offsets.

## Why not just read Vergilius

[Vergilius](https://www.vergiliusproject.com) is the real comparison, and it is
good at what it does. The differences that matter:

| | Vergilius | ntoffsets |
|---|---|---|
| Access | read it in a browser | API, generated headers, runtime blob |
| Updates | manual, lagging | CI |
| Identity | build number | PDB GUID + Age, exact per UBR |
| Global symbol RVAs | no | yes |
| Change tracking | no | diff feed |
| Coverage | unstated | published, including what is missing |
| Verifiable | no | `ntoff verify` re-derives any published value |

## Misuse

The same offsets serve EDR, DFIR, hypervisor and driver developers, and also
whoever else reads them. Vergilius has published equivalent data for years; the
marginal uplift here is small and the set of legitimate users is much larger.

## License

MIT for the code. Data derived from Microsoft symbols is published under the
terms described in the design document; PDBs and binaries are never
redistributed.
