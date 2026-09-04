"""ntoff -- build the offset database.

    python -m ntoff collect --dataset ga --channel 11-24H2
    python -m ntoff collect --dataset arm64 --stratified 8
    python -m ntoff gate --local
    python -m ntoff validate
    python -m ntoff status

`collect` is the pipeline: enumerate from Winbindex, resolve each build's PDB
key over HTTP ranges, fetch symbols from msdl, extract, cross-check against
DIA, and write the content-addressed store.

The DIA cross-check is on by default and `--no-oracle` turns it off. That is
the right default even though it costs time: the oracle is what stands between
a quietly wrong offset and someone's bugcheck (6.3), and on Windows it costs
about a tenth of a second per build.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from . import config, coverage, diff, extract, msdl, site as site_mod, store as store_mod, winbindex
from .compare import compare
from .model import Extraction
from .ntpe import read_pe_info
from .validate import check_self_consistency

REPO = Path(__file__).resolve().parents[1]
LOCAL_KERNEL = Path(r"C:\Windows\System32\ntoskrnl.exe")


def _compared(requested: list[str], oracle, subject) -> list[str]:
    """Which type names the oracle comparison should examine.

    The union, not the oracle's list. Comparing only what DIA found meant a
    type the subject invented was never looked at, and that is precisely how
    the `<unnamed-tag>` chimera survived a passing gate: DIA had no such type,
    so the comparison skipped it and the self-consistency check had to catch it
    instead. A gate that cannot see what the subject added is not a gate.
    """
    if requested == ["*"]:
        return sorted(set(oracle.types) | set(subject.types))
    return requested


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cache", type=Path, default=REPO / "cache")
    parser.add_argument("--data", type=Path, default=REPO / "data")
    parser.add_argument("--work", type=Path, default=REPO / "cache" / "extractions")


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------


def cmd_collect(args: argparse.Namespace) -> int:
    allowlist = config.load()
    types = list(allowlist.gate_types if args.gate_only else allowlist.types)
    symbols = list(allowlist.symbols)
    enum_names = [] if args.gate_only else list(config.enums())

    snapshot = winbindex.fetch_snapshot(
        args.cache, args.dataset, args.file, refresh=args.refresh
    )
    candidates = winbindex.load_candidates(snapshot)
    downloadable = len(candidates)
    undownloadable = winbindex.undownloadable(snapshot)
    known = downloadable + undownloadable

    dataset_name = f"{args.dataset}/{args.file}"
    ledger = coverage.Ledger(args.data / "index" / "unresolved.json")

    if args.channel:
        candidates = [c for c in candidates if args.channel in c.channels]
    if args.p0:
        candidates = [
            c for c in candidates
            if set(c.channel_names) & set(winbindex.P0_CHANNELS)
        ]
    candidates = (
        winbindex.stratified(candidates, args.stratified)
        if args.stratified
        else winbindex.newest_first(candidates)
    )
    if args.limit:
        candidates = candidates[: args.limit]

    store = store_mod.Store(args.data)
    if not args.force:
        # Resuming is the normal case for a backfill of any size: a run that
        # dies at build 150 of 191 must not start over, least of all against a
        # free service we have promised to go easy on (4.3).
        already = store.known_sources()
        before = len(candidates)
        candidates = [c for c in candidates if c.sha256 not in already]
        if before != len(candidates):
            print(f"resuming: {before - len(candidates)} of {before} already in the store")

    print(f"{args.dataset}/{args.file}: {known} indexed, {len(candidates)} to do")
    if not candidates:
        print("nothing to do")
        return 0

    def progress(position, total, candidate, key, outcome, fetched):
        label = f"{candidate.version or '(no version)':<18}{','.join(candidate.channel_names)[:22]:<24}"
        detail = key.key if key else outcome
        print(f"  key [{position}/{total}] {label} {detail}")

    def note(position, total, candidate, key, outcome, fetched):
        # `duplicate_key` is recorded too. It is not a gap -- the build is in
        # the store, reached through a different index entry -- but leaving it
        # unrecorded made the entry vanish from both sides of the arithmetic
        # and reappear as "never attempted", which is the opposite of true.
        if outcome != "ok":
            ledger.record(candidate.sha256, outcome, dataset_name, candidate)
        if args.verbose:
            progress(position, total, candidate, key, outcome, fetched)

    resolved, reasons = winbindex.resolve(
        candidates, file_name=args.file, on_progress=note,
        key_cache=winbindex.KeyCache(args.cache / "pdb-keys.json"),
    )
    print(f"resolved {len(resolved)}/{len(candidates)} PDB keys"
          f"  ({sum(r.bytes_fetched for r in resolved)/1024/1024:.1f} MiB of headers)")

    if args.oracle:
        from . import dia  # imported lazily: Windows-only, never on the CI path

    extract.build()
    universe = store.universe()

    written = reused = skipped = failed = mismatched = 0
    downloaded = 0
    started = time.monotonic()

    for position, item in enumerate(resolved, start=1):
        key = item.key
        label = f"{item.candidate.version or '(no version)':<18}"

        try:
            fetched = msdl.fetch_pdb(key.pdb_name, key.key, args.cache)
        except msdl.NotPublished:
            ledger.record(item.candidate.sha256, "pdb_404", dataset_name, item.candidate)
            print(f"  [{position}/{len(resolved)}] {label} no symbols published")
            skipped += 1
            continue
        downloaded += fetched.bytes_downloaded

        try:
            extraction = extract.run(
                fetched.path, key.key, types, symbols,
                args.work / f"{key.key}.rust.json", enums=enum_names,
            )
        except Exception as error:
            ledger.record(item.candidate.sha256, "parse_failed", dataset_name, item.candidate)
            print(f"  [{position}/{len(resolved)}] {label} extract failed: {error}")
            failed += 1
            continue

        findings = check_self_consistency(extraction)
        if findings.errors:
            # Incoherent output never reaches the store. It is a bug in us,
            # not a gap in the input, and it goes to the defect queue (11).
            ledger.record(item.candidate.sha256, "inconsistent", dataset_name, item.candidate)
            print(f"  [{position}/{len(resolved)}] {label} INCONSISTENT: {findings.errors[0]}")
            failed += 1
            continue

        if args.oracle:
            oracle = dia.extract(fetched.path, types, symbols, key.key,
                                 enum_names=enum_names)
            oracle.write(args.work / f"{key.key}.dia.json")
            report = compare(oracle, extraction, _compared(types, oracle, extraction))
            if not report.passed:
                # DIA wins every disagreement. Storing a value we cannot defend
                # is the one outcome worse than storing nothing.
                ledger.record(item.candidate.sha256, "oracle_mismatch",
                              dataset_name, item.candidate)
                print(f"  [{position}/{len(resolved)}] {label} ORACLE MISMATCH "
                      f"({len(report.fatal)}): {report.fatal[0][1]}")
                mismatched += 1
                continue

        result = store.write_layout(extraction)
        store.write_build(item.candidate, key, extraction, result.layout_hash,
                          args.file, universe=universe)
        ledger.clear(item.candidate.sha256)
        written += result.layout_written
        reused += not result.layout_written

        print(f"  [{position}/{len(resolved)}] {label} "
              f"{'new layout' if result.layout_written else 'same layout'} "
              f"{result.layout_hash.split(':')[-1][:12]}")

    universe.save()
    elapsed = time.monotonic() - started
    index = store.rebuild_indexes()
    stats = store.stats()

    # Index entries with no download URL at all are permanent gaps; record them
    # by hash so re-running does not double count (11).
    stored = store.known_sources()
    for candidate_sha, candidate in _undownloadable_entries(snapshot):
        if candidate_sha not in stored:
            ledger.record(candidate_sha, "undownloadable", dataset_name, candidate)
    ledger.save()

    datasets = coverage.merge_dataset(
        args.data / "index" / "datasets.json", dataset_name, known, downloadable,
        winbindex.channel_totals(snapshot),
    )
    # The datasets overlap, so the denominator is the union `census` recorded,
    # not the sum of their sizes. Without this a `collect` run would quietly
    # inflate `known` again by the 84 builds listed in two indexes.
    universe_path = args.data / "index" / "universe.json"
    distinct = (json.loads(universe_path.read_text(encoding="utf-8"))["known_distinct"]
                if universe_path.exists() else None)
    report = coverage.build_report(datasets, store.read_builds(), ledger, distinct)
    coverage.write(report, args.data / "index")

    print(f"\n{'=' * 68}")
    print(f"store: {stats['builds']} builds, {stats['layouts']} layouts, "
          f"{stats['universe_names']:,} symbol names "
          f"({stats['layout_bytes']/1024/1024:.1f} manifests + "
          f"{stats['type_bytes']/1024/1024:.1f} types + "
          f"{stats['symbol_bytes']/1024/1024:.1f} symbols + "
          f"{stats['build_bytes']/1024/1024:.1f} builds MiB)")
    print(f"this run: {written} new layouts, {reused} deduplicated, "
          f"{skipped} no symbols, {failed} failed, {mismatched} oracle mismatch")
    print(f"          {downloaded/1024/1024:.0f} MiB downloaded in {elapsed:.0f}s")
    print(f"index: {index['count']} versions, coverage "
          f"{report['totals']['resolved']}/{report['totals']['known']}"
          f" ({report['totals']['accounted_missing']} accounted missing,"
          f" {report['totals']['unattempted']} unattempted)")
    if report["defects"]:
        print(f"DEFECTS: {report['defects']} build(s) failed on our side, not the input's")
    if mismatched or failed:
        return 1
    return 0


def _undownloadable_entries(snapshot: Path):
    """Index entries from which no msdl URL can be built at all.

    They never reach `resolve`, so nothing else would record them, and an
    unexplained gap is exactly what 11 says we must not ship.

    The test has to be the same one `load_candidates` uses. It was not: this
    swept for entries missing `virtualSize` while the loader had learned to
    reconstruct it from the last section (4.2), so 26 builds that had just been
    collected successfully were marked missing immediately afterwards. A
    coverage report that contradicts the store is worse than no report.
    """
    import gzip

    index = json.loads(gzip.open(snapshot, "rb").read())
    for sha256, entry in index.items():
        info = entry.get("fileInfo") or {}
        if info.get("timestamp") and winbindex._size_candidates(info):
            continue
        yield sha256, winbindex.Candidate(
            sha256=sha256,
            version=(info.get("version") or "").split(" ")[0],
            machine=info.get("machineType") or 0,
            timestamp=0,
            size_of_image=0,
            channels={c: [] for c in (entry.get("windowsVersions") or {})},
        )


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


def cmd_census(args: argparse.Namespace) -> int:
    """Record how large every dataset is, without collecting any of it.

    The coverage denominator was only counting datasets a `collect` run had
    touched, so Insider -- 421 builds we had never fetched -- was not missing
    from the report, it was absent from the question. 11 is about saying what
    we do not have; a gap that is not in the denominator cannot be said.
    """
    total = 0
    seen: set[str] = set()
    for dataset in sorted(winbindex.DATASETS):
        try:
            snapshot = winbindex.fetch_snapshot(
                args.cache, dataset, args.file, refresh=args.refresh
            )
        except Exception as error:
            print(f"  {dataset:<10} unavailable: {type(error).__name__} {error}")
            continue

        candidates = winbindex.load_candidates(snapshot)
        blocked = winbindex.undownloadable(snapshot)
        known = len(candidates) + blocked
        total += known
        seen.update(_index_hashes(snapshot))
        coverage.merge_dataset(
            args.data / "index" / "datasets.json", f"{dataset}/{args.file}",
            known, len(candidates), winbindex.channel_totals(snapshot),
        )
        print(f"  {dataset:<10} {known:>5} indexed, {len(candidates):>5} fetchable, "
              f"{blocked:>3} with no usable URL")

    coverage.set_universe(args.data / "index" / "universe.json", args.file, len(seen))

    store = store_mod.Store(args.data)
    ledger = coverage.Ledger(args.data / "index" / "unresolved.json")
    datasets = json.loads(
        (args.data / "index" / "datasets.json").read_text(encoding="utf-8")
    )
    report = coverage.build_report(datasets, store.read_builds(), ledger, len(seen))
    coverage.write(report, args.data / "index")
    print(f"\n{args.file}: {len(seen)} distinct builds across "
          f"{len(winbindex.DATASETS)} datasets "
          f"({total - len(seen)} listed in more than one); "
          f"{report['totals']['resolved']} resolved")
    return 0


def _index_hashes(snapshot: Path) -> set[str]:
    """Every content hash an index lists, for deduplicating the denominator."""
    import gzip

    return set(json.loads(gzip.open(snapshot, "rb").read()))


def cmd_gate(args: argparse.Namespace) -> int:
    from . import dia

    allowlist = config.load()
    types = list(allowlist.gate_types if args.gate_only else allowlist.types)
    symbols = list(allowlist.symbols)
    enum_names = [] if args.gate_only else list(config.enums())

    targets: list[tuple[str, str, str]] = []
    if args.local:
        key = read_pe_info(LOCAL_KERNEL).pdb_key
        targets.append((key.key, key.pdb_name, "local"))
    for build in store_mod.Store(args.data).read_builds():
        symbol_key = build.get("symbol_key") or build["key"].replace("-", "")
        if args.local and symbol_key == targets[0][0]:
            continue
        targets.append((symbol_key, build["pdb_name"],
                        build.get("file_version") or f"{build['machine']} {symbol_key[:10]}"))
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        print("nothing to gate; run `collect` first")
        return 1

    extract.build()
    passed = failed = 0
    findings: list[str] = []

    for position, (key, pdb_name, label) in enumerate(targets, start=1):
        fetched = msdl.fetch_pdb(pdb_name, key, args.cache)
        oracle = dia.extract(fetched.path, types, symbols, key, enum_names=enum_names)
        subject = extract.run(fetched.path, key, types, symbols,
                              args.work / f"{key}.rust.json", enums=enum_names)
        report = compare(oracle, subject, _compared(types, oracle, subject))
        if report.passed:
            passed += 1
        else:
            failed += 1
            findings.extend(f"{label} {name}: {message}" for name, message in report.fatal[:4])
        print(f"  [{position}/{len(targets)}] {label:<18} "
              f"{'PASS' if report.passed else f'FAIL {len(report.fatal)}':<8} "
              f"{report.checked_types} types / {report.checked_members} members "
              f"({report.checked_bitfields} bf) / {report.checked_enums} enums "
              f"({report.checked_constants} consts)")

    print(f"\ngate: {passed} pass, {failed} fail")
    for line in findings[:30]:
        print(f"  {line}")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# validate / status
# ---------------------------------------------------------------------------


def cmd_validate(args: argparse.Namespace) -> int:
    paths = sorted(args.work.glob("*.rust.json"))
    if not paths:
        print(f"no extractions in {args.work}; run `collect` first")
        return 1

    errors = warnings = 0
    lines: list[str] = []
    loaded: dict[str, Extraction] = {}

    for path in paths:
        extraction = Extraction.load(path)
        loaded[extraction.pdb_key] = extraction
        findings = check_self_consistency(extraction)
        errors += len(findings.errors)
        warnings += len(findings.warnings)
        lines.extend(f"ERROR {m}" for m in findings.errors)
        lines.extend(f"warn  {m}" for m in findings.warnings)

    # 13.4. This had stopped being called at all during a CLI refactor -- the
    # function was still there, still tested, and reachable from nothing. It is
    # the check that caught `_KPRCB.NodeRelativeTopologyIndex` moving, and a
    # check nobody runs protects nobody.
    continuity = _check_continuity_across(store_mod.Store(args.data), loaded)
    warnings += len(continuity)
    lines.extend(f"warn  {m}" for m in continuity)

    print(f"{len(paths)} extraction(s): {errors} error(s), {warnings} warning(s)"
          f"  [{len(continuity)} continuity]")

    # One line per distinct finding, with how many builds show it. The same
    # sentence repeated 313 times is not 313 findings, and printing it that way
    # buries the twenty that differ.
    grouped = Counter(lines)
    for message, count in grouped.most_common(args.max_findings):
        print(f"  {message}" + (f"   x{count}" if count > 1 else ""))
    if len(grouped) > args.max_findings:
        print(f"  ... {len(grouped) - args.max_findings} more distinct finding(s)")
    return 0 if errors == 0 else 1


def _check_continuity_across(store, loaded: dict[str, Extraction]) -> list[str]:
    """Compare each build with its neighbour in the same channel and machine.

    Both axes matter (13.4): `_KPRCB` moves tens of kilobytes between Windows
    versions, and 22000 amd64 shares a version number with 22000 ARM64 and
    almost no layout.
    """
    from .validate import check_continuity

    runs: dict[tuple[str, str], list[tuple[tuple, str, str]]] = {}
    for build in store.read_builds():
        key = build.get("symbol_key")
        if key not in loaded:
            continue
        order = (build.get("release_date") or "",
                 diff.version_key(build.get("file_version")))
        for channel in build.get("channel") or ["unknown"]:
            runs.setdefault((channel, build["machine"]), []).append(
                (order, key, build.get("file_version") or key[:10])
            )

    messages: list[str] = []
    for (channel, machine), entries in sorted(runs.items()):
        entries.sort()
        for (_, before_key, before_label), (_, after_key, after_label) in zip(
            entries, entries[1:]
        ):
            findings = check_continuity(
                loaded[before_key], loaded[after_key],
                f"{channel} {machine} {before_label}->{after_label}",
            )
            messages.extend(findings.warnings)
            messages.extend(findings.errors)
    return messages


def cmd_feed(args: argparse.Namespace) -> int:
    store = store_mod.Store(args.data)
    if not store.read_builds():
        print("nothing to diff; run `collect` first")
        return 1

    report_path = args.data / "index" / "coverage.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None

    feed = diff.build_feed(store, report)
    written = diff.write(feed, args.data / "feed", base_url=args.base_url)

    # A sequence holding one build has nothing to compare, which is not the
    # same as having compared and found nothing. Conflating the two would turn
    # 10.1's useful "nothing moved" signal into a meaningless one.
    checked = [q for q in feed.sequences if q["transitions"] > 0]
    quiet = [q for q in checked if q["layout_changes"] == 0]
    single = len(feed.sequences) - len(checked)

    print(f"{len(feed.sequences)} sequence(s), {sum(q['transitions'] for q in feed.sequences)} "
          f"transitions, {len(feed.changes)} with a layout change")
    for sequence in feed.sequences:
        gaps = sequence["known_missing_in_channel"]
        verdict = ("nothing to compare" if sequence["transitions"] == 0
                   else f"{sequence['layout_changes']} changes")
        print(f"  {sequence['channel']:<10} {sequence['machine']:<6} "
              f"{sequence['builds']:>3} builds  {verdict:<20}"
              + (f" {gaps} known missing in channel" if gaps else ""))
    if quiet:
        # 10.1: this is the answer most months, and it is the useful one.
        print(f"  -- {len(quiet)} sequence(s) compared with no layout change")
    if single:
        print(f"  -- {single} sequence(s) hold a single build: not yet a signal")

    confirmed = {(r.type_name, r.old, r.new) for r in feed.renames if r.kind == "rename"}
    other = {(r.type_name, r.old, r.new): r.kind
             for r in feed.renames if r.kind != "rename"}
    if confirmed:
        print(f"\nrenames confirmed and aliased: {len(confirmed)}")
        for type_name, old_name, new_name in sorted(confirmed)[:10]:
            print(f"  {type_name}.{old_name} -> {new_name}")
    if other:
        # Same bytes, new name, but the meaning moved rather than the label.
        # Aliasing these would point a caller at a field that stopped being
        # what they asked for.
        print(f"\nnot aliased, meaning changed rather than the label: {len(other)}")
        for (type_name, old_name, new_name), kind in sorted(other.items())[:10]:
            print(f"  {type_name}.{old_name} -> {new_name}  [{kind}]")
    if feed.ambiguous:
        print(f"\nambiguous, needs a human: {len(feed.ambiguous)}")
        for item in feed.ambiguous[:5]:
            print(f"  {item['type']} @ {item['offset']:#x}: "
                  f"{item['removed']} -> {item['added']}")

    print()
    for name, path in written.items():
        print(f"  {path}  ({path.stat().st_size/1024:.1f} KiB)")
    return 0


def cmd_site(args: argparse.Namespace) -> int:
    stats = site_mod.build(args.data, args.out_dir)
    print(f"site: {stats['files']} files, {stats['bytes']/1024/1024:.1f} MiB "
          f"({stats['builds']} builds, {stats['layouts']} layouts)")
    print(f"  {args.out_dir}")
    print(f"\n  python -m http.server 8000 --directory {args.out_dir}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    store = store_mod.Store(args.data)
    stats = store.stats()
    print(f"store {args.data}")
    print(f"  builds       {stats['builds']:>5}  ({stats['build_bytes']/1024/1024:.1f} MiB)")
    print(f"  layouts      {stats['layouts']:>5}  ({stats['layout_bytes']/1024/1024:.1f} MiB manifests)")
    print(f"  type blobs   {stats['type_blobs']:>5}  ({stats['type_bytes']/1024/1024:.1f} MiB)")
    print(f"  symbol names {stats['universe_names']:>5}  ({stats['symbol_bytes']/1024/1024:.1f} MiB, one shared universe)")
    if stats["builds"] and stats["layouts"]:
        print(f"  dedup   {stats['builds']/stats['layouts']:.2f}:1")

    report_path = args.data / "index" / "coverage.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        totals = report["totals"]
        print(f"\ncoverage as of {report['as_of']}")
        print(f"  known {totals['known']}, resolved {totals['resolved']}, "
              f"accounted missing {totals['accounted_missing']}, "
              f"duplicate entries {totals.get('duplicate_entries', 0)}, "
              f"unattempted {totals['unattempted']}")
        if report["missing_reasons"]:
            print(f"  reasons: {report['missing_reasons']}")
        if report.get("defects"):
            print(f"  DEFECTS (ours to fix): {report['defects']}")
        if report.get("no_version_metadata"):
            print(f"  resolved but not findable by version: {report['no_version_metadata']}")
        print(f"  by machine: {report['by_machine']}")
        print(f"  by dataset: {report['by_dataset']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # A backfill runs for tens of minutes. Block buffering makes it look hung
    # the moment output is piped or redirected, which is exactly when someone
    # is most likely to want to see how far it has got.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(prog="ntoff", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="run the pipeline into the store")
    collect.add_argument("--dataset", default="ga", choices=sorted(winbindex.DATASETS))
    collect.add_argument("--file", default="ntoskrnl.exe")
    collect.add_argument("--channel")
    collect.add_argument("--p0", action="store_true", help="restrict to the P0 tier (4.3)")
    collect.add_argument("--stratified", type=int, metavar="N")
    collect.add_argument("--limit", type=int)
    collect.add_argument("--refresh", action="store_true",
                         help="re-download the Winbindex snapshot (2.2: at most daily)")
    collect.add_argument("--gate-only", action="store_true")
    collect.add_argument("--no-oracle", dest="oracle", action="store_false",
                         help="skip the DIA cross-check (Linux, or a deliberate fast path)")
    collect.add_argument("--force", action="store_true",
                         help="redo builds already in the store instead of resuming")
    collect.add_argument("--verbose", action="store_true")
    _add_common(collect)
    collect.set_defaults(func=cmd_collect, oracle=True)

    census = sub.add_parser("census", help="count every dataset, collecting none (11)")
    census.add_argument("--file", default="ntoskrnl.exe")
    census.add_argument("--refresh", action="store_true")
    _add_common(census)
    census.set_defaults(func=cmd_census)

    gate = sub.add_parser("gate", help="re-read every stored build with both parsers")
    gate.add_argument("--local", action="store_true")
    gate.add_argument("--gate-only", action="store_true")
    gate.add_argument("--limit", type=int)
    _add_common(gate)
    gate.set_defaults(func=cmd_gate)

    validate = sub.add_parser("validate", help="self-consistency over stored extractions")
    validate.add_argument("--max-findings", type=int, default=25)
    _add_common(validate)
    validate.set_defaults(func=cmd_validate)

    feed = sub.add_parser("feed", help="diff feed: what changed between builds (10)")
    feed.add_argument("--base-url", default="https://ntoffsets.github.io/ntoffsets")
    _add_common(feed)
    feed.set_defaults(func=cmd_feed)

    site = sub.add_parser("site", help="assemble the static site (8.1, 8.4)")
    site.add_argument("--out-dir", type=Path, default=REPO / "site")
    _add_common(site)
    site.set_defaults(func=cmd_site)

    status = sub.add_parser("status", help="store size, dedup ratio, coverage")
    _add_common(status)
    status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
