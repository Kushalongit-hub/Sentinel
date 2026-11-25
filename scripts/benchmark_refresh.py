"""Measure native Sentinel refresh and optional focused context; never run fixture code."""
import argparse
import json
import math
import platform
from pathlib import Path
import subprocess
import tempfile
import time

from benchmark import digest


def native_identity(value):
    # Generated fixture paths/sources are ASCII; match Sentinel's compact JSON SHA-256.
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def summarize(rows):
    values = sorted(row["elapsed_ms"] for row in rows if row["status"] == "complete")
    return {"samples": len(rows), "complete": len(values),
            "p50_ms": values[math.ceil(len(values) * .5) - 1] if values else None,
            "p95_ms": values[math.ceil(len(values) * .95) - 1] if values else None}


def measure(binary, root, count, changed, timeout):
    started = time.perf_counter()
    row = {"status": "failed"}
    try:
        result = subprocess.run([str(binary), "index", str(root)], capture_output=True,
                                text=True, encoding="utf-8", timeout=timeout)
        stats = json.loads(result.stdout)
        if not isinstance(stats, dict) or type(stats.get("complete")) is not bool:
            raise ValueError("invalid index completeness")
        if not isinstance(stats.get("coverage_notes"), list):
            raise ValueError("invalid index coverage notes")
        for key in ("files_indexed", "changed_files", "unchanged_files"):
            if type(stats.get(key)) is not int or stats[key] < 0:
                raise ValueError("invalid index counters")
        row.update(index=stats, exit_code=result.returncode)
        if not stats["complete"]:
            if result.returncode != 2:
                raise ValueError("contradictory incomplete index exit code")
            row["status"] = "partial"
        elif (result.returncode != 0 or stats["files_indexed"] != count
              or stats["changed_files"] != changed or stats["unchanged_files"] != count - changed):
            raise ValueError("index scope or refresh counters contradict the fixture")
        else:
            row["status"] = "complete"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        row["error"] = type(error).__name__ + ": " + str(error)[:500]
    row["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return row


def measure_context(binary, root, timeout, expected_snapshot):
    started = time.perf_counter()
    row = {"status": "failed", "expected_source_snapshot": expected_snapshot}
    try:
        result = subprocess.run([str(binary), "context", "helper_0", "--project", str(root),
                                 "--max-items", "40"], capture_output=True,
                                text=True, encoding="utf-8", timeout=timeout)
        context = json.loads(result.stdout)
        if not isinstance(context, dict) or type(context.get("complete")) is not bool:
            raise ValueError("invalid context completeness")
        if context.get("target") != "helper_0" or not isinstance(context.get("coverage_notes"), list):
            raise ValueError("invalid context target or coverage notes")
        if not isinstance(context.get("backend"), dict) or context["backend"].get("name") != "sentinel-native":
            raise ValueError("missing native context backend")
        snapshot = context.get("source_snapshot")
        if not isinstance(snapshot, str) or len(snapshot) != 64 or any(c not in "0123456789abcdef" for c in snapshot):
            raise ValueError("missing context source identity")
        for key in ("omitted_count", "omitted_target_symbols"):
            if type(context.get(key)) is not int or context[key] < 0:
                raise ValueError("invalid context omission counters")
        for key in ("target_symbols", "selected_items"):
            if not isinstance(context.get(key), list) or len(context[key]) > 40:
                raise ValueError("invalid bounded context arrays")
        if not context["selected_items"]:
            raise ValueError("fixture context evidence absent")
        if not any(isinstance(symbol, dict) and symbol.get("name") == "helper_0"
                   and isinstance(symbol.get("location"), dict)
                   and symbol["location"].get("file") == "module_00000.py"
                   for symbol in context["target_symbols"]):
            raise ValueError("fixture target absent from context")
        row.update(context=context, exit_code=result.returncode)
        if result.returncode != (0 if context["complete"] else 2):
            raise ValueError("context completeness contradicts exit code")
        if context["complete"] and snapshot != expected_snapshot:
            raise ValueError("complete context source identity contradicts current fixture")
        row["status"] = "complete" if context["complete"] else "partial"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        row["error"] = type(error).__name__ + ": " + str(error)[:500]
    row["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--cold-repeats", type=int, default=1)
    parser.add_argument("--context", action="store_true", help="also measure warm and edited focused static context")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.files <= 10000 or not 1 <= args.repeats <= 30 or not 1 <= args.cold_repeats <= 10 or not 0 < args.timeout <= 600:
        parser.error("files 1..10000, repeats 1..30, cold repeats 1..10, timeout (0,600]")
    if args.output.exists():
        parser.error("output must be new")
    binary = args.binary.resolve(strict=True)
    binary_hash = digest(binary.read_bytes())
    manifest = {}
    graph_manifest = {}
    groups = {"cold": [], "warm": [], "one_file_changed": []}
    if args.context:
        groups.update(context_warm=[], context_one_file_changed=[])
    with tempfile.TemporaryDirectory(prefix="sentinel-refresh-benchmark-") as directory:
        for sample in range(args.cold_repeats):
            root = Path(directory) / f"cold_{sample}"
            root.mkdir()
            for i in range(args.files):
                name = f"module_{i:05d}.py"
                text = f"def helper_{i}():\n    return 0\n"
                (root / name).write_text(text, encoding="utf-8", newline="\n")
                manifest[name] = digest(text.encode("utf-8"))
                graph_manifest[name] = native_identity(text)
            groups["cold"].append(measure(binary, root, args.files, args.files, args.timeout))
        # Warm/edit samples use the final fresh repository, never reuse a prior cold database.
        for _ in range(args.repeats):
            groups["warm"].append(measure(binary, root, args.files, 0, args.timeout))
        for i in range(args.repeats):
            text = f"def helper_0():\n    return {i + 1}\n"
            (root / "module_00000.py").write_text(text, encoding="utf-8", newline="\n")
            graph_manifest["module_00000.py"] = native_identity(text)
            groups["one_file_changed"].append(measure(binary, root, args.files, 1, args.timeout))
        if args.context:
            for _ in range(args.repeats):
                groups["context_warm"].append(measure_context(binary, root, args.timeout, native_identity(graph_manifest)))
            for i in range(args.repeats):
                text = f"def helper_0():\n    return {args.repeats + i + 1}\n"
                (root / "module_00000.py").write_text(text, encoding="utf-8", newline="\n")
                graph_manifest["module_00000.py"] = native_identity(text)
                groups["context_one_file_changed"].append(measure_context(binary, root, args.timeout, native_identity(graph_manifest)))
    errors = []
    try:
        after_hash = digest(binary.read_bytes())
    except OSError:
        after_hash = None
    if after_hash != binary_hash:
        errors.append("scanner binary changed or became unavailable")
    if any(row["status"] != "complete" for rows in groups.values() for row in rows):
        errors.append("one or more measurements failed or omitted fixture scope")
    report = {"schema_version": 1, "binary_sha256": binary_hash,
              "binary_sha256_after": after_hash, "measurement_valid": not errors,
              "measurement_errors": errors, "requested_files": args.files,
              "repeats": args.repeats, "cold_repeats": args.cold_repeats, "timeout_seconds": args.timeout,
              "context_measured": args.context,
              "fixture_newlines": "lf",
              "platform": platform.platform(), "python_version": platform.python_version(),
              "fixture_sha256": digest(json.dumps(manifest, sort_keys=True).encode("utf-8")),
              "scope": "Synthetic independent Python modules; wall time includes startup and SQLite. Cold means fresh database, not cold OS caches. Nearest-rank percentiles use complete samples only; small samples are descriptive. No memory, cancellation or competitor measurement.",
              "summary": {name: summarize(rows) for name, rows in groups.items()}, "samples": groups}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"summary": report["summary"], "measurement_errors": errors}, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
