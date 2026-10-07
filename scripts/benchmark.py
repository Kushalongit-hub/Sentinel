"""Run labelled static-analysis cases through Sentinel; never execute fixture code."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import tempfile
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate(corpus):
    if not isinstance(corpus, dict) or corpus.get("schema_version") != 1 or not isinstance(corpus.get("cases"), list) or not corpus["cases"]:
        raise ValueError("expected schema_version 1 and nonempty cases")
    if len(corpus["cases"]) > 10000:
        raise ValueError("corpus exceeds 10000 cases")
    ids, families = set(), {}
    for case in corpus["cases"]:
        if not isinstance(case, dict) or any(not isinstance(case.get(key), str) or not case[key].strip()
                for key in ("id", "family", "class", "split")):
            raise ValueError("expected nonempty case identity, family, class and split")
        if case["id"] in ids:
            raise ValueError("duplicate case id")
        ids.add(case["id"])
        if case["split"] not in ("development", "holdout"):
            raise ValueError("invalid split")
        if families.setdefault(case["family"], case["split"]) != case["split"]:
            raise ValueError("family leaks between development and holdout")
        if type(case.get("positive")) is not bool or not isinstance(case.get("rules"), list) or not case["rules"] or any(
                not isinstance(rule, str) or not rule.strip() for rule in case["rules"]) or not isinstance(case.get("files"), dict) or not case["files"]:
            raise ValueError("expected truth label, rule mapping and files")
        if case.get("engine", "rules") not in ("rules", "graph"):
            raise ValueError("unsupported engine")
        if case.get("engine") == "graph" and case.get("entrypoint") not in case["files"]:
            raise ValueError("graph entrypoint must belong to fixture files")
        if len(case["files"]) > 2000:
            raise ValueError("fixture exceeds 2000 files")
        portable_names, source_bytes = set(), 0
        for name, source in case["files"].items():
            # Portable paths prevent Windows drive, backslash and traversal escapes.
            if not isinstance(name, str) or not name or "\\" in name or ":" in name or name.startswith("/") or any(
                part in ("", ".", "..") for part in name.split("/")
            ) or not isinstance(source, str):
                raise ValueError("invalid fixture path or source")
            for part in name.split("/"):
                stem = part.split(".")[0].upper()
                if part.endswith((".", " ")) or any(ord(c) < 32 or c in '<>"|?*' for c in part) or stem in (
                        "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))):
                    raise ValueError("fixture path is not portable")
                if part.casefold().startswith(".sentinel.db") or part.casefold() == ".git":
                    raise ValueError("fixture overlaps scanner state")
            folded = name.casefold()
            if folded in portable_names:
                raise ValueError("fixture paths collide on case-insensitive filesystems")
            portable_names.add(folded)
            size = len(source.encode("utf-8"))
            source_bytes += size
            if size > 1024 * 1024 or source_bytes > 16 * 1024 * 1024:
                raise ValueError("fixture exceeds source byte budget")
        for name in portable_names:
            parts = name.split("/")
            if any("/".join(parts[:i]) in portable_names for i in range(1, len(parts))):
                raise ValueError("fixture file conflicts with a parent directory")


def validate_report(report, exit_code):
    if not isinstance(report, dict) or exit_code not in (0, 1) or report.get("outcome") != "Complete":
        raise ValueError("scan failed, was incomplete, or returned a contradictory exit code")
    findings = report.get("findings")
    if not isinstance(findings, list) or any(not isinstance(f, dict) or any(
            not isinstance(f.get(key), str) or not f[key] for key in ("title", "severity")) or
            type(f.get("line")) is not int or f["line"] < 1 for f in findings):
        raise ValueError("malformed findings")
    if type(report.get("files_scanned")) is not int or report["files_scanned"] < 0:
        raise ValueError("malformed scan count")
    notes = report.get("coverage_notes")
    if not isinstance(notes, list) or any(not isinstance(note, str) for note in notes):
        raise ValueError("malformed coverage notes")
    scanners = report.get("scanner_results")
    if not isinstance(scanners, list) or not scanners or any(
            not isinstance(scanner, dict) or scanner.get("outcome") != "Completed" for scanner in scanners):
        raise ValueError("missing or incomplete scanner results")


def rate(successes, total):
    if not total:
        return {"value": None, "wilson_95": None, "denominator": 0}
    p, z = successes / total, 1.959963984540054
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {"value": p, "wilson_95": [center - margin, center + margin], "denominator": total}


def score(rows):
    counts = dict(tp=0, fp=0, tn=0, fn=0, failed=0)
    for row in rows:
        if row["status"] != "complete":
            counts["failed"] += 1
            continue
        key = ("tp" if row["detected"] else "fn") if row["positive"] else (
            "fp" if row["detected"] else "tn")
        counts[key] += 1
    return {**counts, "precision": rate(counts["tp"], counts["tp"] + counts["fp"]),
            "recall": rate(counts["tp"], counts["tp"] + counts["fn"]),
            "complete_cases": len(rows) - counts["failed"], "total_cases": len(rows)}


def run_case(binary, case, timeout):
    row = {key: case[key] for key in ("id", "family", "class", "split", "positive")}
    row["source_sha256"] = digest(json.dumps(case["files"], sort_keys=True).encode())
    row["engine"] = case.get("engine", "rules")
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sentinel-benchmark-") as directory:
        root = Path(directory)
        for name, source in case["files"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8", newline="\n")
        try:
            command = ([str(binary), "scan-file", case["entrypoint"], "--project", str(root)]
                       if row["engine"] == "graph" else
                       [str(binary), "audit", str(root), "--format", "json", "--db", str(root / ".sentinel.db")])
            result = subprocess.run(command,
                                    cwd=root, capture_output=True, timeout=timeout, check=False)
            report = json.loads(result.stdout)
            if row["engine"] == "graph":
                if not isinstance(report, dict) or not isinstance(report.get("taint"), dict) or report["taint"].get("complete") is not True:
                    raise ValueError("graph trace is missing or incomplete")
                row["trace_complete"] = report["taint"]["complete"]
                report = report["report"]
            validate_report(report, result.returncode)
            findings = report["findings"]
            row.update(status="complete", detected=any(f["title"] in case["rules"] for f in findings),
                       findings=[{k: f[k] for k in ("title", "line", "severity")} for f in findings],
                       unscored_findings=sum(f["title"] not in case["rules"] for f in findings),
                       coverage_notes=report["coverage_notes"], files_scanned=report["files_scanned"])
            expected_files = 1 if row["engine"] == "graph" else len(case["files"])
            if row["files_scanned"] != expected_files or row.get("trace_complete") is False:
                row.update(status="failed", error="fixture files were not fully scanned")
        except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, TypeError) as error:
            row.update(status="failed", error=str(error)[:1000])
    row["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=Path(__file__).resolve().parents[1] / "benchmarks/seed.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--split", choices=("development", "holdout", "all"), default="development")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    binary = args.binary.resolve(strict=True)
    raw = args.corpus.read_bytes()
    corpus = json.loads(raw)
    validate(corpus)
    selected = [c for c in corpus["cases"] if args.split == "all" or c["split"] == args.split]
    if not selected:
        parser.error("selected split has no cases")
    rows = [run_case(binary, case, args.timeout) for case in selected]
    report = {"schema_version": 1, "corpus_sha256": digest(raw),
              "binary_sha256": digest(binary.read_bytes()), "split": args.split,
              "scope": "case-level detection of mapped rules; additional findings are unscored",
              "summary": score(rows), "per_class": {
                  category: score([r for r in rows if r["class"] == category])
                  for category in sorted({r["class"] for r in rows})}, "per_engine": {
                  engine: score([r for r in rows if r["engine"] == engine])
                  for engine in sorted({r["engine"] for r in rows})}, "cases": rows}
    # Refuse overwrite so earlier benchmark evidence cannot disappear by accident.
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps(report["summary"], indent=2))
    return 2 if report["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
