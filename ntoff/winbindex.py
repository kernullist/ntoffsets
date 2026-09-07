"""Winbindex: which kernels exist, and where to get them.

Winbindex answers the file identity question and stops there (2.1). Two of its
properties shape this module, and both were found by measurement rather than
by reading the docs (0.5):

**It publishes no PDB GUIDs** (F1). Every build we index has to have its binary
read for the CodeView record, so the "skip the binary when the GUID is already
known" path in the original design does not exist. Ranged reads make that
affordable -- about 48 KiB per build instead of the whole 8-14 MB image.

**It is three repositories, split by architecture as well as channel** (F2).
The site serves x86 and amd64; ARM64 and Insider live on their own gh-pages
branches and are not linked from it. Treating the served index as the whole
dataset silently loses an entire architecture.

Politeness shapes the rest (2.2): the snapshot is fetched whole and queried
locally rather than crawled, and the binary reads are serialized and spaced.
"""

from __future__ import annotations

import gzip
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import msdl, version
from .ntpe import PdbKey, PeFormatError, ShortRead, read_pe_info

# The three repositories do not share a layout. GA and ARM64 put every file at
# the top of `by_filename_compressed/`; Insider sh 256-way, and the shard is not
# derivable from the name by any hash we could find -- `ntoskrnl.exe` lives in
# `f0/`, which is neither its sha256, sha1 nor md5 prefix. So the shard is
# looked up from the repository tree once and cached.
#
# This entry sat in the table unexercised until the day it was needed, and it
# was wrong: a dataset nobody had run was a dataset nobody had tested.
DATASETS = {
    "ga": "https://winbindex.m417z.com/data/by_filename_compressed/{file}.json.gz",
    "arm64": "https://raw.githubusercontent.com/m417z/winbindex-data-arm64/"
             "gh-pages/by_filename_compressed/{file}.json.gz",
    "insider": "https://raw.githubusercontent.com/m417z/winbindex-data-insider/"
               "gh-pages/by_filename_compressed/{shard}/{file}.json.gz",
}

SHARDED_DATASETS = ("insider",)

_INSIDER_TREE = ("https://api.github.com/repos/m417z/winbindex-data-insider/"
                 "git/trees/gh-pages")

# Recent GA channels resolve first (4.3, P0). Everything else waits for demand.
#
# 4.3 spells the tier out as "11-22H2 onward plus 10-22H2 LTSC", so 11-21H2 is
# P1 despite being tempting to include -- it is 61 builds, a third of the tier
# again, for a channel that is out of support. The tiers exist to keep the
# total request count down (4.3); quietly widening the first one defeats them.
P0_CHANNELS = ("11-26H1", "11-25H2", "11-24H2", "11-23H2", "11-22H2", "22H2")

MACHINE_NAMES = {0x014C: "x86", 0x8664: "amd64", 0xAA64: "arm64"}


@dataclass
class Candidate:
    """One binary, with every channel that shipped it.

    Keyed by content hash rather than by (file, channel), because the same
    binary is published under several channels and KBs (5.3). Resolving per
    channel would read the same image from msdl several times over for a key
    that cannot differ.
    """

    sha256: str
    version: str
    machine: int
    timestamp: int
    size_of_image: int
    channels: dict[str, list[str]] = field(default_factory=dict)
    release_date: str = ""
    # Extra `SizeOfImage` guesses to try when the index omitted the real one.
    size_alternatives: tuple[int, ...] = ()

    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.machine, f"0x{self.machine:04X}")

    @property
    def channel_names(self) -> list[str]:
        return sorted(self.channels)

    @property
    def kbs(self) -> list[str]:
        return sorted({kb for kbs in self.channels.values() for kb in kbs})


@dataclass
class Resolved:
    candidate: Candidate
    key: PdbKey
    bytes_fetched: int


def snapshot_path(cache: Path, dataset: str, file_name: str) -> Path:
    suffix = "" if dataset == "ga" else f".{dataset}"
    return cache / "winbindex" / f"{file_name}{suffix}.json.gz"


def _insider_shard(cache: Path, file_name: str) -> str:
    """Which two-hex directory holds `file_name` in the Insider repository.

    The shard is not derivable from the name -- `ntoskrnl.exe` is in `f0`,
    `ntoskrnl-dl.man` in `47`, and neither matches any prefix or suffix of the
    name's sha256, sha1, md5, crc32 or adler32. So it is read from the
    repository tree.

    The whole mapping is stored on the first miss rather than one entry at a
    time. Unauthenticated GitHub API calls are limited to sixty an hour, and
    adding `win32k.sys` later should not spend another one.
    """
    index_path = cache / "winbindex" / "insider-shards.json"
    shards: dict[str, str] = {}
    if index_path.exists():
        shards = json.loads(index_path.read_text(encoding="utf-8"))
    if file_name in shards:
        return shards[file_name]

    root = json.loads(_get(_INSIDER_TREE))
    subtree = next(t["sha"] for t in root["tree"]
                   if t["path"] == "by_filename_compressed")
    listing = json.loads(_get(f"{_INSIDER_TREE.rsplit('/', 1)[0]}/{subtree}?recursive=1"))

    for entry in listing["tree"]:
        path = entry["path"]
        if entry["type"] != "blob" or not path.endswith(".json.gz") or "/" not in path:
            continue
        shard, name = path.split("/", 1)
        shards[name[: -len(".json.gz")]] = shard

    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(shards, separators=(",", ":")), encoding="utf-8")

    if file_name not in shards:
        raise FileNotFoundError(f"{file_name} is not in the Insider dataset")
    return shards[file_name]


def _get(url: str, *, attempts: int = 4) -> bytes:
    """Read one GitHub API response, with a token when we have one.

    Anonymous API calls are limited to sixty an hour **per IP**, and a CI
    runner's address is shared with every other job on the fleet, so the quota
    is usually gone before we ask. `GITHUB_TOKEN` raises the limit and makes it
    ours; the first CI run failed here with a 500 on the tree listing while the
    same call had always worked from a laptop.

    Retried on 5xx for the same reason `msdl.fetch` is: the tree of the Insider
    repository is tens of thousands of entries and the API sheds load on it.
    """
    headers = {
        # Not the symbol-server user agent: the GitHub API rejects it with a 500.
        "User-Agent": "ntoffsets/0.1 (+https://github.com/ntoffsets)",
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    delay = 2.0
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if attempt == attempts or error.code < 500:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == attempts:
                raise
        time.sleep(delay)
        delay *= 2
    raise AssertionError("unreachable")


def snapshot_url(cache: Path, dataset: str, file_name: str) -> str:
    template = DATASETS[dataset]
    if dataset in SHARDED_DATASETS:
        return template.format(file=file_name, shard=_insider_shard(cache, file_name))
    return template.format(file=file_name)


def fetch_snapshot(cache: Path, dataset: str, file_name: str, *, refresh: bool = False) -> Path:
    destination = snapshot_path(cache, dataset, file_name)
    if refresh and destination.exists():
        destination.unlink()
    msdl.fetch(snapshot_url(cache, dataset, file_name), destination)
    return destination


def _size_candidates(info: dict) -> list[int]:
    """Possible `SizeOfImage` values when the index does not carry one.

    The msdl binary key is timestamp plus image size (4.2), so an entry without
    `virtualSize` looked permanently unfetchable and was recorded as such. It
    is not: Winbindex still publishes the last section's virtual address and
    raw offset, and

        align(lastSectionVirtualAddress + (size - lastSectionPointerToRawData))

    lands within two pages of the answer. Measured against all 527 entries that
    carry *both* the real size and those fields, the difference is 0x2000 in
    353 cases and 0x3000 in the other 174 -- never anything else. The slack is
    the Authenticode overlay, which `size` includes and the image does not.

    So two candidates cover every observed case, and a 404 on both is then a
    real absence rather than an arithmetic gap.
    """
    if info.get("virtualSize"):
        return [info["virtualSize"]]
    last_va = info.get("lastSectionVirtualAddress")
    last_raw = info.get("lastSectionPointerToRawData")
    if not last_va or not last_raw or not info.get("size"):
        return []
    tail = info["size"] - last_raw
    aligned = (last_va + tail + 0xFFF) & ~0xFFF
    return [size for size in (aligned - 0x2000, aligned - 0x3000) if size > 0]


def load_candidates(snapshot: Path) -> list[Candidate]:
    index = json.loads(gzip.open(snapshot, "rb").read())
    candidates: list[Candidate] = []

    for sha256, entry in index.items():
        info = entry.get("fileInfo") or {}
        sizes = _size_candidates(info)
        if not info.get("timestamp") or not sizes:
            # Without a timestamp and at least one plausible size, no download
            # URL exists at all (4.2). Coverage data, not a silent drop.
            continue

        candidate = Candidate(
            sha256=sha256,
            version=(info.get("version") or "").split(" ")[0],
            machine=info.get("machineType") or 0,
            timestamp=info["timestamp"],
            size_of_image=sizes[0],
            size_alternatives=tuple(sizes[1:]),
        )

        dates: list[str] = []
        for channel, updates in (entry.get("windowsVersions") or {}).items():
            kbs = sorted(kb for kb in updates if kb != "BASE")
            candidate.channels[channel] = kbs
            dates.extend(
                (updates[kb].get("updateInfo") or {}).get("releaseDate", "") for kb in kbs
            )
        candidate.release_date = min((d for d in dates if d), default="")
        candidates.append(candidate)

    return candidates


def channel_totals(snapshot: Path) -> dict[str, int]:
    """How many builds each channel actually contains.

    Without this the coverage report can only say how many builds we tried and
    failed on, which reads as "this channel is nearly complete" for a channel
    we never touched. 11 exists to prevent exactly that impression.
    """
    index = json.loads(gzip.open(snapshot, "rb").read())
    totals: dict[str, int] = defaultdict(int)
    for entry in index.values():
        for channel in (entry.get("windowsVersions") or {}):
            totals[channel] += 1
    return dict(totals)


def undownloadable(snapshot: Path) -> int:
    """Index entries with no usable download URL, for the coverage report."""
    index = json.loads(gzip.open(snapshot, "rb").read())
    return sum(
        1
        for entry in index.values()
        if not ((entry.get("fileInfo") or {}).get("timestamp")
                and _size_candidates(entry.get("fileInfo") or {}))
    )


def newest_first(candidates: list[Candidate]) -> list[Candidate]:
    return sorted(candidates, key=lambda c: version.sort_key(c.version), reverse=True)


def stratified(candidates: list[Candidate], count: int) -> list[Candidate]:
    """One build per channel, newest first, until `count` is reached.

    A parser breaks on the eras it has never seen, so breadth across channels
    buys more confidence per download than depth inside one. Useless for
    measuring layout convergence, though -- that needs consecutive builds in a
    single channel (M2).

    Channels are split by Windows version where the label covers more than one
    (`version.mixed_channels`). Breadth is the entire point here, and the
    Insider dataset's single `builds` channel spans 19041 to 28000 -- left
    whole it contributes one candidate for every era it holds, which is the
    opposite of stratifying.
    """
    mixed = version.mixed_channels(
        (candidate.channel_names, candidate.version) for candidate in candidates
    )
    by_channel: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        for channel in candidate.channel_names:
            label = version.channel_label(channel, candidate.version, mixed)
            if label is not None:
                by_channel[label].append(candidate)
    for builds in by_channel.values():
        builds.sort(key=lambda c: version.sort_key(c.version), reverse=True)

    ordered = sorted(
        by_channel.values(),
        key=lambda builds: version.sort_key(builds[0].version),
        reverse=True,
    )

    picked: list[Candidate] = []
    taken: set[str] = set()
    depth = 0
    while len(picked) < count and depth < 200:
        progressed = False
        for builds in ordered:
            if depth >= len(builds):
                continue
            progressed = True
            candidate = builds[depth]
            if candidate.sha256 in taken:
                continue
            taken.add(candidate.sha256)
            picked.append(candidate)
            if len(picked) == count:
                return picked
        if not progressed:
            break
        depth += 1
    return picked


class KeyCache:
    """Winbindex hash to PDB key, kept outside the store.

    A build's PDB key is a fact about a file that will never change, so asking
    msdl for it twice is pure waste. Keeping the mapping only inside the store
    meant that rebuilding the store re-read 191 binaries over the network --
    exactly the traffic 4.3 promises not to generate.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, dict] = {}
        if path.exists():
            self.entries = json.loads(path.read_text(encoding="utf-8"))
        self._dirty = False

    def get(self, sha256: str) -> PdbKey | None:
        entry = self.entries.get(sha256)
        if not entry:
            return None
        return PdbKey(uuid.UUID(entry["guid"]), entry["age"], entry["pdb_name"])

    def put(self, sha256: str, key: PdbKey) -> None:
        self.entries[sha256] = {
            "guid": str(key.guid), "age": key.age, "pdb_name": key.pdb_name,
        }
        self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(dict(sorted(self.entries.items())), indent=0), encoding="utf-8"
        )
        self._dirty = False


def resolve(
    candidates: list[Candidate],
    *,
    file_name: str = "ntoskrnl.exe",
    on_progress=None,
    key_cache: "KeyCache | None" = None,
) -> tuple[list[Resolved], dict[str, int]]:
    """Read each binary's CodeView record over HTTP ranges (4.4)."""
    resolved: list[Resolved] = []
    seen: set[str] = set()
    reasons: dict[str, int] = defaultdict(int)

    for position, candidate in enumerate(candidates, start=1):
        cached = key_cache.get(candidate.sha256) if key_cache else None
        if cached is not None:
            # The cached path has to report a duplicate as one. Reporting "ok"
            # for every cache hit meant that on a run where every key came from
            # the cache -- which is every run after the first -- duplicates were
            # recorded nowhere, and the coverage arithmetic showed them as
            # builds nobody had attempted.
            if cached.key in seen:
                outcome = "duplicate_key"
            else:
                outcome = "ok"
                seen.add(cached.key)
                resolved.append(Resolved(candidate, cached, 0))
            if outcome != "ok":
                reasons[outcome] += 1
            if on_progress:
                on_progress(position, len(candidates), candidate, cached, outcome, 0)
            continue

        outcome = "ok"
        key = None
        reader = None

        for size in (candidate.size_of_image, *candidate.size_alternatives):
            url = msdl.binary_url(file_name, candidate.timestamp, size)
            reader = msdl.RangedReader(url)
            try:
                key = read_pe_info(reader).pdb_key
                # Record the size that actually worked. When the index omits
                # `virtualSize` we try two reconstructions (4.2), and leaving
                # the first guess in place wrote a wrong `size_of_image` into
                # the build entry -- one of the two fields 5.3 uses to identify
                # the image, and the one that rebuilds the download URL.
                candidate.size_of_image = size
                candidate.size_alternatives = ()
                if key_cache:
                    key_cache.put(candidate.sha256, key)
                outcome = "ok"
                break
            except msdl.NotPublished:
                outcome = "binary_404"
            except (PeFormatError, ShortRead):
                outcome = "pe_parse_failed"
                break
            except Exception:
                # Network faults are coverage data too; a run that dies partway
                # through a backfill is worse than one that records the gap.
                outcome = "fetch_error"
                break

        if key is not None:
            if key.key in seen:
                outcome = "duplicate_key"
            else:
                seen.add(key.key)
                resolved.append(Resolved(candidate, key, reader.bytes_fetched))

        if outcome != "ok":
            reasons[outcome] += 1
        if on_progress:
            on_progress(position, len(candidates), candidate, key, outcome, reader.bytes_fetched)

    if key_cache:
        key_cache.save()
    return resolved, dict(reasons)
