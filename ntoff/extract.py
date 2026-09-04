"""Drives the Rust extractor.

The parser that ships is `crates/ntoff-extract`, because it runs on a Linux CI
runner with nothing installed but a Rust toolchain (3). This module is the thin
layer that gets a PDB in front of it and reads the result back.

The DIA oracle in `dia.py` reads the same PDB a second time, and the two are
compared before anything reaches the store. That comparison is not a formality:
it caught a parser bug that invented 96 `_EPROCESS` members and dropped 4 real
ones, with every offset still looking plausible (6.3).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .model import Extraction

REPO = Path(__file__).resolve().parents[1]
CRATE = "ntoff-extract"


class ExtractorMissing(RuntimeError):
    pass


def binary_path() -> Path:
    name = "ntoff-extract.exe" if _on_windows() else "ntoff-extract"
    return REPO / "target" / "release" / name


def _on_windows() -> bool:
    import sys

    return sys.platform.startswith("win")


def _cargo() -> str:
    found = shutil.which("cargo")
    if found:
        return found
    # rustup installs here and does not always put it on PATH.
    fallback = Path.home() / ".cargo" / "bin" / ("cargo.exe" if _on_windows() else "cargo")
    if fallback.exists():
        return str(fallback)
    raise ExtractorMissing("cargo not found; install a Rust toolchain")


def build(*, quiet: bool = True) -> Path:
    command = [_cargo(), "build", "--release", "-p", CRATE]
    if quiet:
        command.insert(2, "-q")
    subprocess.run(command, cwd=REPO, check=True)
    return binary_path()


def run(pdb: Path, key: str, types: list[str], symbols: list[str], out: Path,
        enums: list[str] | None = None) -> Extraction:
    executable = binary_path()
    if not executable.exists():
        raise ExtractorMissing(f"{executable} not built; run `build()` first")

    out.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            str(executable),
            "--pdb", str(pdb),
            "--key", key,
            "--types", ",".join(types),
            "--enums", ",".join(enums or []),
            "--symbols", ",".join(symbols),
            "--out", str(out),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ntoff-extract failed: {result.stderr.strip()}")
    return Extraction.load(out)
