"""Assembles the static site (8.1, 8.4).

Everything the site serves is a file on disk. No server, no database, no
request handling -- that is the point of 8.1, and it is what makes GitHub Pages
sufficient (8.4).

One documented deviation. 8.1 lists `GET /v1/resolve?version=10.0.26100.4061`,
and a query string cannot be answered by static hosting. The resolution happens
in the browser instead, against `v1/index/by-version.json`, so the URL becomes
`#/version/10.0.26100.4061`. Same answer, no server; the JSON index is public
either way, so a script can do the same lookup without the page.

The layout files dominate the byte count -- 43 layouts against 237 builds, and
each layout is two orders of magnitude larger than the build entry pointing at
it. That ratio is why 8.4 puts layouts and builds in their own repositories:
the site repo stays small enough to keep its history, and the data repos can be
truncated. This builder emits one tree because that is what a local preview
needs; the split is a deployment concern, not a format one.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .store import Store

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "web"


def _compact_builds(builds: list[dict]) -> dict:
    """A single index the browser can search without fetching 237 files.

    Short field names because this is the one file every visitor downloads.
    """
    return {
        "schema": 1,
        "count": len(builds),
        "builds": [
            {
                "k": build["symbol_key"],
                "v": build.get("file_version"),
                "m": build["machine"],
                "c": build.get("channel") or [],
                "kb": build.get("kb") or [],
                "d": build.get("release_date"),
                "l": build["layout"].split(":")[-1],
                "y": build.get("symbol_count", 0),
                "n": build["pdb_name"],
            }
            for build in sorted(
                builds,
                key=lambda b: (b.get("release_date") or "", b.get("file_version") or ""),
                reverse=True,
            )
        ],
    }


def _compact_layouts(builds: list[dict], store: Store) -> dict:
    """Which builds share each layout -- the content addressing, made visible."""
    used: dict[str, list[str]] = {}
    for build in builds:
        used.setdefault(build["layout"], []).append(build["symbol_key"])

    entries = []
    for digest, keys in sorted(used.items(), key=lambda kv: -len(kv[1])):
        manifest = store.read_manifest(digest)
        entries.append({
            "hash": digest.split(":")[-1],
            "types": len(manifest.get("types") or {}),
            "enums": len(manifest.get("enums") or {}),
            "builds": sorted(keys),
        })
    return {"schema": 1, "count": len(entries), "layouts": entries}


def build(data: Path, out: Path) -> dict:
    store = Store(data)
    builds = store.read_builds()
    if not builds:
        raise SystemExit("store is empty; run `collect` first")

    if out.exists():
        shutil.rmtree(out)
    api = out / "v1"
    (api / "build").mkdir(parents=True)
    (api / "layout").mkdir(parents=True)
    (api / "feed").mkdir(parents=True)
    (api / "index").mkdir(parents=True)

    for build_document in builds:
        (api / "build" / f"{build_document['symbol_key']}.json").write_text(
            json.dumps(build_document, indent=1), encoding="utf-8"
        )

    layout_dir = data / "layouts" / "v1"
    for path in layout_dir.glob("*.json"):
        shutil.copy2(path, api / "layout" / path.name)

    (api / "type").mkdir(parents=True, exist_ok=True)
    type_dir = data / "types" / "v1"
    if type_dir.is_dir():
        for path in type_dir.glob("*.json"):
            shutil.copy2(path, api / "type" / path.name)

    (api / "symbols").mkdir(parents=True, exist_ok=True)
    universe = data / "symbols" / "universe.json"
    if universe.exists():
        shutil.copy2(universe, api / "symbols" / "universe.json")

    for name in ("changes.json", "changes.xml", "aliases.json", "renames-review.json"):
        source = data / "feed" / name
        if source.exists():
            shutil.copy2(source, api / "feed" / name)

    for name, destination in (("coverage.json", api / "coverage.json"),
                              ("by-version.json", api / "index" / "by-version.json")):
        source = data / "index" / name
        if source.exists():
            shutil.copy2(source, destination)

    (api / "index" / "builds.json").write_text(
        json.dumps(_compact_builds(builds), indent=None, separators=(",", ":")),
        encoding="utf-8",
    )
    (api / "index" / "layouts.json").write_text(
        json.dumps(_compact_layouts(builds, store), indent=None, separators=(",", ":")),
        encoding="utf-8",
    )

    for path in WEB.iterdir():
        if path.is_file():
            shutil.copy2(path, out / path.name)

    files = sorted(out.rglob("*"))
    return {
        "files": sum(1 for f in files if f.is_file()),
        "bytes": sum(f.stat().st_size for f in files if f.is_file()),
        "builds": len(builds),
        "layouts": len(list((api / "layout").glob("*.json"))),
    }
