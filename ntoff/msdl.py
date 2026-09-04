"""Symbol server client.

Deliberately polite (4.3): serialized requests, a delay between them, ETag
caching, and exponential backoff. We do not rotate proxies or otherwise work
around throttling -- a project that has to hide from its own upstream does not
last. The cache is what keeps the request count down across runs.

Nothing fetched here is ever redistributed (12). The cache holds Microsoft's
PDBs; only the parsed offsets leave this machine.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

# msdl rejects or degrades requests that do not look like a symbol client.
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

MSCF_MAGIC = b"MSCF"

_MIN_REQUEST_INTERVAL = 1.0
_last_request = 0.0


class NotPublished(Exception):
    """The symbol server has no file under this key.

    A normal outcome, not a failure (4.2): plenty of builds never had symbols
    published. Callers record it as coverage data.
    """


@dataclass
class FetchResult:
    path: Path
    from_cache: bool
    bytes_downloaded: int
    seconds: float


def pdb_url(pdb_name: str, key: str) -> str:
    return f"{SYMBOL_SERVER}/{pdb_name}/{key}/{pdb_name}"


def binary_url(file_name: str, timestamp: int, size_of_image: int) -> str:
    return f"{SYMBOL_SERVER}/{file_name}/{timestamp:X}{size_of_image:X}/{file_name}"


def _throttle() -> None:
    global _last_request
    elapsed = time.monotonic() - _last_request
    if elapsed < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request = time.monotonic()


def _expand_cab(cab: Path, destination: Path) -> None:
    """Unpack an MSCF container.

    The server may answer with a compressed form whose extension ends in `_`
    (4.2). Even when the name says `.pdb`, the body can still be a cab, so we
    dispatch on the magic rather than the name.
    """
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            ["expand.exe", str(cab), "-F:*", tmp],
            capture_output=True,
            text=True,
        )
        extracted = sorted(Path(tmp).iterdir())
        if result.returncode != 0 or not extracted:
            raise RuntimeError(f"cab expansion failed: {result.stdout}{result.stderr}")
        shutil.move(str(extracted[0]), str(destination))


def fetch(url: str, destination: Path, *, attempts: int = 4) -> FetchResult:
    if destination.exists() and destination.stat().st_size > 0:
        return FetchResult(destination, True, 0, 0.0)

    destination.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    delay = 2.0

    for attempt in range(1, attempts + 1):
        _throttle()
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                body = response.read()
            break
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise NotPublished(url) from error
            if attempt == attempts or error.code < 500:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == attempts:
                raise
        time.sleep(delay)
        delay *= 2

    staging = destination.with_suffix(destination.suffix + ".part")
    staging.write_bytes(body)
    if body[:4] == MSCF_MAGIC:
        _expand_cab(staging, destination)
        staging.unlink(missing_ok=True)
    else:
        staging.replace(destination)

    return FetchResult(destination, False, len(body), time.monotonic() - started)


class RangedReader:
    """Random access over an msdl-hosted file without downloading it.

    Winbindex publishes no PDB GUIDs, so every build has to have its binary
    read to find one (4.4). Whole kernels are 8 to 14 MB each; the CodeView
    record is under a hundred bytes. Reading only what we need is what keeps a
    thousand-build backfill inside a rounding error of msdl's bandwidth
    instead of a dozen gigabytes of it.

    Ranges are coalesced through a small block cache because the header reads
    are clustered at the front of the file and would otherwise each cost a
    round trip.
    """

    BLOCK = 16384

    def __init__(self, url: str) -> None:
        self.url = url
        self.requests = 0
        self.bytes_fetched = 0
        self._blocks: dict[int, bytes] = {}

    def __call__(self, offset: int, size: int) -> bytes:
        if size <= 0:
            return b""
        first = offset // self.BLOCK
        last = (offset + size - 1) // self.BLOCK

        missing = [index for index in range(first, last + 1) if index not in self._blocks]
        for start, end in _runs(missing):
            self._load(start, end)

        buffer = b"".join(self._blocks[index] for index in range(first, last + 1))
        start_in_buffer = offset - first * self.BLOCK
        return buffer[start_in_buffer : start_in_buffer + size]

    def _load(self, first: int, last: int) -> None:
        begin = first * self.BLOCK
        end = (last + 1) * self.BLOCK - 1

        _throttle()
        request = urllib.request.Request(
            self.url,
            headers={"User-Agent": USER_AGENT, "Range": f"bytes={begin}-{end}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                body = response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise NotPublished(self.url) from error
            raise

        self.requests += 1
        self.bytes_fetched += len(body)

        for index in range(first, last + 1):
            chunk = body[(index - first) * self.BLOCK : (index - first + 1) * self.BLOCK]
            # A short final block means end of file; cache it as is so a read
            # past the end raises ShortRead rather than looping.
            self._blocks[index] = chunk


def _runs(indices: list[int]) -> list[tuple[int, int]]:
    """Collapse a sorted index list into contiguous (first, last) runs."""
    runs: list[tuple[int, int]] = []
    for index in indices:
        if runs and index == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], index)
        else:
            runs.append((index, index))
    return runs


def fetch_pdb(pdb_name: str, key: str, cache_dir: Path) -> FetchResult:
    destination = cache_dir / "pdb" / key / pdb_name
    try:
        return fetch(pdb_url(pdb_name, key), destination)
    except NotPublished:
        # The compressed form lives at its own path; try it before giving up.
        compressed = pdb_name[:-1] + "_"
        return fetch(pdb_url(compressed, key), destination)
