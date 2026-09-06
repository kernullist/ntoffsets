"""Assembles the static site (8.1, 8.4).

Everything the site serves is a file on disk. No server, no database, no
request handling -- that is the point of 8.1, and it is what makes GitHub Pages
sufficient (8.4).

One documented deviation. 8.1 lists `GET /v1/resolve?version=10.0.26100.4061`,
and a query string cannot be answered by static hosting. The resolution happens
in the browser instead, against `v1/index/by-version.json`, so the URL becomes
`#/version/10.0.26100.4061`. Same answer, no server; the JSON index is public
either way, so a script can do the same lookup without the page.

**The output splits by how often a file changes, not by channel.** 8.4
originally proposed per-channel repositories, following Winbindex. That does
not survive content addressing: 66% of type bodies are shared across channels
and 55% across architectures, so a per-channel split would either duplicate two
thirds of them or need cross-repository references for the shared part --
undoing the saving that made per-type addressing worth doing (7.2).

What does divide cleanly is mutability:

* the site, indexes, feed and coverage change on every run and are small;
* the addressed data is immutable once written and is almost all of the bytes.

Keeping them apart means a re-extraction -- which rewrites every manifest --
churns only the data repository, and its history can be truncated without
losing the code's. `--data-out` emits that second tree; without it everything
lands in one, which is what a local preview wants.

When the two are served from different origins, the page needs to be told. It
reads `v1/config.json`, which the site repo carries; an empty `data_base`
means same origin, so the single-tree build needs no special case.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import diff
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


def _compact_names(builds: list[dict], store: Store) -> dict:
    """Every type and enum name we hold, with how many distinct definitions.

    Without this there is no way into the struct data at all. A layout manifest
    is a map of hashes, so it answers "what is _EPROCESS in this build" but not
    "what types are there" -- and a reader who does not already know the name
    has nowhere to start. 519 manifests is not something a page can scan.

    Names only, plus a variant count and the newest layout that defines each.
    61 KiB for 2,505 names, against 161 KiB to also list every variant, and the
    count is what a reader acts on: one definition means the type is identical
    in every build we hold, forty means it is not. Newest rather than any, so
    opening a name shows a definition that is still shipping.
    """
    seen: dict[str, dict[str, dict]] = {"types": {}, "enums": {}}
    # Newest first, and one pass per distinct layout rather than per build:
    # 519 manifests, not 1,967 reads of the same few hundred.
    done: set[str] = set()
    for build in sorted(builds, key=diff.order_key, reverse=True):
        digest = build["layout"]
        if digest in done:
            continue
        done.add(digest)
        manifest = store.read_manifest(digest)
        layout = digest.split(":")[-1]
        for kind in ("types", "enums"):
            for name, body in (manifest.get(kind) or {}).items():
                entry = seen[kind].setdefault(name, {"variants": set(), "layout": layout})
                entry["variants"].add(body)

    return {
        "schema": 1,
        **{kind: {name: [len(entry["variants"]), entry["layout"]]
                  for name, entry in sorted(names.items())}
           for kind, names in seen.items()},
    }


def _measure(root: Path) -> tuple[int, int]:
    files = [f for f in root.rglob("*") if f.is_file()] if root.exists() else []
    return len(files), sum(f.stat().st_size for f in files)


def build(data: Path, out: Path, data_out: Path | None = None,
          data_base: str = "") -> dict:
    """Assemble the site, optionally splitting the addressed data into its own tree.

    `data_base` is the URL the page should fetch that data from. Empty means
    same origin, which is both the single-tree case and the sane default: a
    page that has to be told where its own data is will eventually be told
    wrong.
    """
    store = Store(data)
    builds = store.read_builds()
    if not builds:
        raise SystemExit("store is empty; run `collect` first")

    if out.exists():
        shutil.rmtree(out)
    if data_out is not None and data_out.exists():
        shutil.rmtree(data_out)

    site_api = out / "v1"
    data_root = data_out if data_out is not None else out
    data_api = data_root / "v1"

    for directory in (site_api / "feed", site_api / "index",
                      data_api / "build", data_api / "layout",
                      data_api / "type", data_api / "symbols"):
        directory.mkdir(parents=True, exist_ok=True)

    for build_document in builds:
        (data_api / "build" / f"{build_document['symbol_key']}.json").write_text(
            json.dumps(build_document, indent=1), encoding="utf-8"
        )

    # From the store's own directories, not a hardcoded schema generation:
    # the layout schema moves (LAYOUT_SCHEMA_VERSION) and a builder that names
    # the previous one publishes an empty tree, or worse, a stale one.
    #
    # And only what is reachable. A content-addressed store never deletes, so a
    # layout written by a run that was later corrected stays on disk forever
    # with nothing pointing at it -- the v1 tree carried two. Publishing the
    # directory wholesale ships that garbage to every mirror and grows the data
    # repository with files no consumer can arrive at.
    live_layouts = {build["layout"].split(":")[-1] for build in builds}
    live_types: set[str] = set()
    for digest in sorted(live_layouts):
        path = store.layouts / f"{digest}.json"
        if not path.exists():
            raise SystemExit(f"build references layout {digest}, which is not in the store")
        shutil.copy2(path, data_api / "layout" / path.name)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for kind in ("types", "enums"):
            live_types.update((manifest.get(kind) or {}).values())

    if store.types.is_dir():
        for digest in sorted(live_types):
            path = store.types / f"{digest}.json"
            if not path.exists():
                raise SystemExit(f"manifest references type {digest}, which is not in the store")
            shutil.copy2(path, data_api / "type" / path.name)

    universe = store.universe_path
    if universe.exists():
        shutil.copy2(universe, data_api / "symbols" / "universe.json")

    for name in ("changes.json", "changes.xml", "aliases.json", "renames-review.json"):
        source = data / "feed" / name
        if source.exists():
            shutil.copy2(source, site_api / "feed" / name)

    for name, destination in (("coverage.json", site_api / "coverage.json"),
                              ("by-version.json", site_api / "index" / "by-version.json")):
        source = data / "index" / name
        if source.exists():
            shutil.copy2(source, destination)

    (site_api / "index" / "builds.json").write_text(
        json.dumps(_compact_builds(builds), separators=(",", ":")), encoding="utf-8",
    )
    (site_api / "index" / "layouts.json").write_text(
        json.dumps(_compact_layouts(builds, store), separators=(",", ":")),
        encoding="utf-8",
    )
    (site_api / "index" / "names.json").write_text(
        json.dumps(_compact_names(builds, store), separators=(",", ":")),
        encoding="utf-8",
    )
    (site_api / "config.json").write_text(
        json.dumps({"schema": 1, "data_base": data_base.rstrip("/")}, indent=1),
        encoding="utf-8",
    )

    for path in WEB.iterdir():
        if path.is_file():
            shutil.copy2(path, out / path.name)

    # Without this GitHub Pages runs Jekyll over the tree, which silently drops
    # anything it decides is a source file. Nothing here is a Jekyll site and
    # 8.4 already wants the build step skipped, so say so in the tree rather
    # than depending on a repository setting nobody can see from here.
    (out / ".nojekyll").write_text("", encoding="utf-8")
    if data_out is not None:
        (data_out / ".nojekyll").write_text("", encoding="utf-8")

    site_files, site_bytes = _measure(out)
    if data_out is None:
        return {"files": site_files, "bytes": site_bytes, "builds": len(builds),
                "layouts": len(list((data_api / "layout").glob("*.json"))),
                "split": False}

    data_files, data_bytes = _measure(data_out)
    return {
        "files": site_files, "bytes": site_bytes,
        "data_files": data_files, "data_bytes": data_bytes,
        "builds": len(builds),
        "layouts": len(list((data_api / "layout").glob("*.json"))),
        "split": True,
    }
