"""Score fixed static graph queries; fixture source is never executed."""
import argparse
import json
import math
from pathlib import Path
import subprocess
import tempfile
import time

from benchmark import digest, rate, validate_files


def identity(value):
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def validate(corpus):
    if not isinstance(corpus, dict) or corpus.get("schema_version") != 1 or not isinstance(corpus.get("cases"), list) or not 1 <= len(corpus["cases"]) <= 10000:
        raise ValueError("expected schema 1 and 1..10000 query cases")
    if "label_status" in corpus and (not isinstance(corpus["label_status"], str) or not corpus["label_status"].strip()):
        raise ValueError("invalid label status")
    ids, families = set(), {}
    for case in corpus["cases"]:
        if not isinstance(case, dict) or any(not isinstance(case.get(key), str) or not case[key].strip()
                for key in ("id", "family", "class", "split", "target")):
            raise ValueError("missing query identity or target")
        if case["id"] in ids or case["split"] not in ("development", "holdout"):
            raise ValueError("duplicate identity or invalid split")
        ids.add(case["id"])
        if families.setdefault(case["family"], case["split"]) != case["split"]:
            raise ValueError("family leaks between development and holdout")
        if case.get("command") not in ("symbols", "callers", "callees", "trace") or len(case["target"].encode("utf-8")) > 512 or case["target"].startswith("-"):
            raise ValueError("unsupported query command or target")
        validate_files(case.get("files"))
        if case.get("symbol_names", "name") not in ("name", "qualified"):
            raise ValueError("symbol_names must be name or qualified")
        expected = case.get("expected")
        if "trace_steps" in case and (case["command"] != "trace" or type(case["trace_steps"]) is not bool):
            raise ValueError("trace_steps is a boolean trace-only option")
        if case["command"] == "trace":
            if case.get("symbol_names", "qualified") != "qualified":
                raise ValueError("trace symbols use qualified names")
            if not isinstance(expected, dict) or set(expected) != {"paths"}:
                raise ValueError("expected exact trace endpoint paths")
            if not isinstance(expected["paths"], list) or len(expected["paths"]) > 200:
                raise ValueError("invalid expected trace paths")
            for path in expected["paths"]:
                if not isinstance(path, list) or len(path) != (4 if case.get("trace_steps") else 3) or not isinstance(path[0], str) or not path[0]:
                    raise ValueError("invalid expected trace path")
                endpoints = path[1:3]
                if case.get("trace_steps"):
                    if not isinstance(path[3], list) or not 1 <= len(path[3]) <= 1000 or path[3][0] != path[1] or path[3][-1] != path[2]:
                        raise ValueError("invalid expected ordered trace boundaries")
                    endpoints += path[3]
                for endpoint in endpoints:
                    if not isinstance(endpoint, list) or len(endpoint) != 3 or not isinstance(endpoint[0], str) or endpoint[0] not in case["files"] or type(endpoint[1]) is not int or endpoint[1] < 1 or not isinstance(endpoint[2], str) or not endpoint[2]:
                        raise ValueError("invalid expected trace endpoint")
            continue
        if not isinstance(expected, dict) or set(expected) not in ({"symbols", "edges"}, {"symbols", "edges", "endpoint_edges"}):
            raise ValueError("expected exact symbol/edge lists")
        if not isinstance(expected["symbols"], list) or any(not isinstance(s, list) or len(s) != 2
                or not isinstance(s[0], str) or s[0] not in case["files"] or not isinstance(s[1], str) or not s[1] for s in expected["symbols"]):
            raise ValueError("invalid expected symbols")
        if not isinstance(expected["edges"], list) or any(not isinstance(e, list) or len(e) != 2
                or not isinstance(e[0], str) or not e[0] or type(e[1]) is not bool for e in expected["edges"]):
            raise ValueError("invalid expected edges")
        if max(len(expected["symbols"]), len(expected["edges"])) > 200:
            raise ValueError("expected output exceeds query limit")
        if "endpoint_edges" in expected:
            if not isinstance(expected["endpoint_edges"], list) or len(expected["endpoint_edges"]) > 200:
                raise ValueError("invalid expected endpoint list")
            for edge in expected["endpoint_edges"]:
                if not isinstance(edge, list) or len(edge) != 4 or not isinstance(edge[2], str) or not edge[2] or type(edge[3]) is not bool:
                    raise ValueError("invalid expected endpoint edge")
                for endpoint in edge[:2]:
                    if endpoint is None:
                        continue
                    if not isinstance(endpoint, list) or len(endpoint) != 2 or not isinstance(endpoint[0], str) or endpoint[0] not in case["files"] or not isinstance(endpoint[1], str) or not endpoint[1]:
                        raise ValueError("invalid expected endpoint symbol")
                if edge[0] is None or (edge[3] and edge[1] is None):
                    raise ValueError("resolved edges require both endpoints; every call requires an owner")
            if sorted([edge[2:] for edge in expected["endpoint_edges"]]) != sorted(expected["edges"]):
                raise ValueError("endpoint labels contradict call-name/resolution labels")


def endpoint_edges(query, files, name_field="name"):
    symbols = {}
    for symbol in query["target"] + query["symbols"]:
        if not isinstance(symbol, dict) or not isinstance(symbol.get("id"), str) or not symbol["id"] or not isinstance(symbol.get(name_field), str) or not symbol[name_field] or not isinstance(symbol.get("location"), dict) or not isinstance(symbol["location"].get("file"), str) or symbol["location"]["file"] not in files:
            raise ValueError("invalid endpoint symbol")
        key = [symbol["location"]["file"], symbol[name_field]]
        if symbol["id"] in symbols and symbols[symbol["id"]] != key:
            raise ValueError("inconsistent symbol identity")
        symbols[symbol["id"]] = key
    output = []
    for edge in query["edges"]:
        if any(not isinstance(edge.get(key), str) or not edge[key] for key in ("from", "to")):
            raise ValueError("missing call endpoint identity")
        owner, callee = symbols.get(edge["from"]), symbols.get(edge["to"])
        if owner is None or (edge["resolved"] and callee is None):
            raise ValueError("call endpoint absent from untruncated symbol output")
        output.append([owner, callee, edge["name"], edge["resolved"]])
    return output


def trace_location(step, files):
    if not isinstance(step, dict) or not isinstance(step.get("symbol"), str) or not step["symbol"] or not isinstance(step.get("location"), dict):
        raise ValueError("invalid trace endpoint")
    location = step["location"]
    if not isinstance(location.get("file"), str) or location["file"] not in files or type(location.get("start_line")) is not int or location["start_line"] < 1:
        raise ValueError("invalid trace endpoint location")
    return [location["file"], location["start_line"], step["symbol"]]


def trace_paths(query, files, with_steps=False):
    paths = query.get("paths")
    if not isinstance(paths, list) or len(paths) > 200:
        raise ValueError("invalid trace paths")
    output = []
    for path in paths:
        if not isinstance(path, dict) or not isinstance(path.get("sink_type"), str) or not path["sink_type"]:
            raise ValueError("invalid trace sink category")
        item = [path["sink_type"]]
        for key in ("source", "sink"):
            item.append(trace_location(path.get(key), files))
        if with_steps:
            steps = path.get("path")
            if not isinstance(steps, list) or not 1 <= len(steps) <= 1000:
                raise ValueError("missing or oversized ordered trace steps")
            steps = [trace_location(step, files) for step in steps]
            if steps[0] != item[1] or steps[-1] != item[2]:
                raise ValueError("ordered trace contradicts source/sink boundaries")
            item.append(steps)
        output.append(item)
    return output


def run_case(binary, case, timeout):
    row = {key: case[key] for key in ("id", "family", "class", "split", "command", "target")}
    row.update(status="failed", source_sha256=identity(case["files"]), expected=case["expected"])
    is_trace = case["command"] == "trace"
    row["symbol_names"] = "qualified" if is_trace else case.get("symbol_names", "name")
    complete_key = "complete" if is_trace else "index_complete"
    if is_trace:
        row["trace_limits"] = {"max_paths": 200, "max_call_depth": 8, "max_nodes_visited": 10000}
        row["trace_steps"] = case.get("trace_steps", False)
    name_field = "qualified_name" if row["symbol_names"] == "qualified" else "name"
    expected_snapshot = identity({name: identity(source) for name, source in case["files"].items()})
    row["expected_source_snapshot"] = expected_snapshot
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sentinel-query-benchmark-") as directory:
        root = Path(directory)
        for name, source in case["files"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8", newline="\n")
        try:
            limits = (["--max-paths", "200", "--max-call-depth", "8", "--max-nodes-visited", "10000"]
                      if is_trace else ["--max-items", "200"])
            result = subprocess.run([str(binary), case["command"], case["target"], "--project", str(root),
                                     *limits], cwd=root, capture_output=True, timeout=timeout)
            query = json.loads(result.stdout)
            row.update(exit_code=result.returncode, query=query)
            if not isinstance(query, dict) or type(query.get(complete_key)) is not bool:
                raise ValueError("missing query completeness")
            if not isinstance(query.get("coverage_notes"), list) or any(not isinstance(n, str) for n in query["coverage_notes"]):
                raise ValueError("invalid query coverage notes")
            if not isinstance(query.get("backend"), dict) or query["backend"].get("name") != "sentinel-native":
                raise ValueError("missing native query backend")
            if result.returncode != (0 if query[complete_key] else 2):
                raise ValueError("query completeness contradicts exit code")
            if not query[complete_key]:
                row["status"] = "partial"
            else:
                if query.get("source_snapshot") != expected_snapshot:
                    raise ValueError("query source identity contradicts full fixture")
                if is_trace:
                    actual = {"paths": trace_paths(query, case["files"], row["trace_steps"])}
                else:
                    if type(query.get("omitted_count")) is not int or query["omitted_count"] != 0:
                        raise ValueError("query output is truncated or has invalid omissions")
                    for key in ("symbols", "edges", "target"):
                        if not isinstance(query.get(key), list) or len(query[key]) > 200:
                            raise ValueError("invalid query arrays")
                    symbols = []
                    for symbol in query["symbols"]:
                        if not isinstance(symbol, dict) or not isinstance(symbol.get(name_field), str) or not symbol[name_field] or not isinstance(symbol.get("location"), dict) or symbol["location"].get("file") not in case["files"]:
                            raise ValueError("invalid returned symbol")
                        symbols.append([symbol["location"]["file"], symbol[name_field]])
                    edges = []
                    for edge in query["edges"]:
                        if not isinstance(edge, dict) or edge.get("kind") != "CALLS" or not isinstance(edge.get("name"), str) or not edge["name"] or type(edge.get("resolved")) is not bool:
                            raise ValueError("invalid returned call edge")
                        edges.append([edge["name"], edge["resolved"]])
                    actual = {"symbols": sorted(symbols), "edges": sorted(edges)}
                    if "endpoint_edges" in case["expected"]:
                        actual["endpoint_edges"] = endpoint_edges(query, case["files"], name_field)
                # JSON keys also order unresolved (null) endpoints alongside named ones.
                actual = {key: sorted(value, key=lambda item: json.dumps(item, sort_keys=True)) for key, value in actual.items()}
                expected = {key: sorted(value, key=lambda item: json.dumps(item, sort_keys=True)) for key, value in case["expected"].items()}
                row.update(status="complete", actual=actual, correct=actual == expected)
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
            row.update(status="failed", error=type(error).__name__ + ": " + str(error)[:500])
    row["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return row


def score(rows):
    complete = [row for row in rows if row["status"] == "complete"]
    correct = sum(row["correct"] for row in complete)
    return {"total": len(rows), "complete": len(complete), "correct": correct,
            "incorrect": len(complete) - correct, "failed_or_partial": len(rows) - len(complete),
            "complete_accuracy": rate(correct, len(complete)), "correct_response_rate": rate(correct, len(rows))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split", choices=("development", "holdout", "all"), default="development")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()
    if args.output.exists() or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("output must be new and timeout positive/finite")
    binary = args.binary.resolve(strict=True)
    before = digest(binary.read_bytes())
    raw = args.corpus.read_bytes()
    corpus = json.loads(raw)
    validate(corpus)
    selected = [case for case in corpus["cases"] if args.split == "all" or case["split"] == args.split]
    if not selected:
        parser.error("selected split has no cases")
    rows = [run_case(binary, case, args.timeout) for case in selected]
    try:
        after = digest(binary.read_bytes())
    except OSError:
        after = None
    errors = []
    if after != before:
        errors.append("scanner binary changed or became unavailable")
    if any(row["status"] != "complete" for row in rows):
        errors.append("one or more query cases failed or were partial")
    report = {"schema_version": 1, "binary_sha256": before, "binary_sha256_after": after,
              "corpus_sha256": digest(raw), "measurement_valid": not errors, "measurement_errors": errors,
              "label_status": corpus.get("label_status", "unspecified; independent adjudication unknown"),
              "split": args.split, "scope": "Exact file/name or opted-in qualified-name symbol multisets and call-name/resolution multisets, with endpoint direction when explicitly labelled. Trace cases score sink category and directed file/line/qualified-symbol endpoints, plus ordered steps when opted in. No operation-text, confidence, type, guard or AI scoring. Labels require independent review.",
              "summary": score(rows), "per_class": {key: score([r for r in rows if r["class"] == key]) for key in sorted({r["class"] for r in rows})},
              "per_split": {key: score([r for r in rows if r["split"] == key]) for key in sorted({r["split"] for r in rows})}, "cases": rows}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps(report["summary"], indent=2))
    return 2 if errors else int(args.fail_on_regression and bool(report["summary"]["incorrect"]))


if __name__ == "__main__":
    raise SystemExit(main())
