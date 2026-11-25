import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from benchmark_queries import identity, main, run_case, score, validate


def case():
    return {"id": "query", "family": "query-family", "class": "symbols", "split": "development",
            "command": "symbols", "target": "helper", "files": {"main.py": "def helper():\n    return 1\n"},
            "expected": {"symbols": [["main.py", "helper"]], "edges": []}}


def response(c):
    return {"index_complete": True, "coverage_notes": [], "backend": {"name": "sentinel-native"},
            "source_snapshot": identity({name: identity(source) for name, source in c["files"].items()}),
            "omitted_count": 0, "target": [], "edges": [],
            "symbols": [{"name": "helper", "location": {"file": "main.py"}}]}


class QueryBenchmarkTests(unittest.TestCase):
    def test_ordered_trace_scoring_detects_missing_and_reordered_intermediate_steps(self):
        locations = [["main.py", i, name] for i, name in enumerate(("source", "service", "repository", "sink"), 1)]
        c = dict(case(), command="trace", trace_steps=True,
            expected={"paths": [["sql-injection", locations[0], locations[-1], locations]]})
        validate({"schema_version": 1, "cases": [c]})
        steps = [{"symbol": location[2], "location": {"file": location[0], "start_line": location[1]}} for location in locations]
        path = {"sink_type": "sql-injection", "source": steps[0], "sink": steps[-1], "path": steps}
        base = {"complete": True, "backend": {"name": "sentinel-native"}, "coverage_notes": [],
                "source_snapshot": response(c)["source_snapshot"]}
        for ordered, status, correct in [(steps, "complete", True),
                ([steps[0], steps[2], steps[1], steps[3]], "complete", False),
                ([steps[0], steps[-1]], "complete", False),
                (list(reversed(steps)), "failed", None), (None, "failed", None),
                ([steps[0]] * 1001, "failed", None)]:
            with self.subTest(ordered=ordered), patch("benchmark_queries.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(dict(base, paths=[dict(path, path=ordered)])).encode(), b"")):
                row = run_case(Path("sentinel"), c, 1)
                self.assertEqual(row["status"], status)
                self.assertEqual(row.get("correct"), correct)
                self.assertTrue(row["trace_steps"])

    def test_ordered_trace_labels_reject_missing_steps_wrong_boundaries_and_wrong_modes(self):
        endpoint = ["main.py", 1, "helper"]
        for c in [dict(case(), trace_steps=True), dict(case(), command="trace", trace_steps=1),
                dict(case(), command="trace", trace_steps=True, expected={"paths": [["sql-injection", endpoint, endpoint]]}),
                dict(case(), command="trace", trace_steps=True, expected={"paths": [["sql-injection", endpoint, endpoint, []]]})]:
            with self.subTest(case=c), self.assertRaises(ValueError):
                validate({"schema_version": 1, "cases": [c]})

    def test_trace_queries_score_directed_locations_and_fail_partial_or_stale_output(self):
        c = dict(case(), command="trace", expected={"paths": [["sql-injection",
            ["main.py", 1, "helper"], ["main.py", 2, "helper"]]]})
        validate({"schema_version": 1, "cases": [c]})
        step = lambda line: {"symbol": "helper", "location": {"file": "main.py", "start_line": line}}
        path = {"sink_type": "sql-injection", "source": step(1), "sink": step(2)}
        base = {"complete": True, "backend": {"name": "sentinel-native"}, "coverage_notes": [],
                "source_snapshot": response(c)["source_snapshot"], "paths": [path]}
        for code, query, status, correct in [(0, base, "complete", True),
                (0, dict(base, paths=[]), "complete", False),
                (0, dict(base, paths=[dict(path, source=step(2), sink=step(1))]), "complete", False),
                (0, dict(base, paths=[dict(path, sink_type="xss")]), "complete", False),
                (0, dict(base, paths=[dict(path, source=step(True))]), "failed", None),
                (0, dict(base, paths=[path] * 201), "failed", None),
                (0, dict(base, source_snapshot="b" * 64), "failed", None),
                (2, dict(base, complete=False), "partial", None),
                (0, dict(base, complete=False), "failed", None)]:
            with self.subTest(query=query), patch("benchmark_queries.subprocess.run",
                    return_value=subprocess.CompletedProcess([], code, json.dumps(query).encode(), b"")) as run:
                row = run_case(Path("sentinel"), c, 1)
                self.assertEqual(row["status"], status)
                self.assertEqual(row.get("correct"), correct)
                self.assertEqual(row["symbol_names"], "qualified")
                self.assertEqual(row["trace_limits"]["max_paths"], 200)
                self.assertIn("--max-paths", run.call_args.args[0])
                self.assertNotIn("--max-items", run.call_args.args[0])

    def test_trace_labels_reject_invalid_locations_and_wrong_contracts(self):
        for expected in [{"symbols": [], "edges": []}, {"paths": [["sql-injection", None, None]]},
                {"paths": [["sql-injection", ["main.py", 0, "helper"], ["main.py", 2, "helper"]]]}]:
            c = dict(case(), command="trace", expected=expected)
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                validate({"schema_version": 1, "cases": [c]})

    def test_qualified_names_distinguish_same_named_methods_and_require_qualified_output(self):
        c = dict(case(), command="callees", target="First.run", symbol_names="qualified",
            expected={"symbols": [["main.py", "First.helper"]], "edges": [["self.helper", True]],
                "endpoint_edges": [[["main.py", "First.run"], ["main.py", "First.helper"], "self.helper", True]]})
        validate({"schema_version": 1, "cases": [c]})
        query = response(c)
        query["target"] = [{"id": "caller", "name": "run", "qualified_name": "First.run", "location": {"file": "main.py"}}]
        query["edges"] = [{"from": "caller", "to": "helper", "name": "self.helper", "resolved": True, "kind": "CALLS"}]
        for qualified, status, correct in [("First.helper", "complete", True),
                ("Second.helper", "complete", False), (None, "failed", None)]:
            query["symbols"][0].update(id="helper", qualified_name=qualified)
            with patch("benchmark_queries.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(query).encode(), b"")):
                row = run_case(Path("sentinel"), c, 1)
                self.assertEqual(row["status"], status)
                self.assertEqual(row.get("correct"), correct)
                self.assertEqual(row["symbol_names"], "qualified")
        bad = dict(c, symbol_names="arbitrary-field")
        with self.assertRaisesRegex(ValueError, "symbol_names"):
            validate({"schema_version": 1, "cases": [bad]})

    def test_endpoint_scoring_detects_reversed_calls_and_rejects_dangling_identities(self):
        c = dict(case(), command="callees", expected={"symbols": [["main.py", "helper"]],
            "edges": [["helper", True]],
            "endpoint_edges": [[["main.py", "caller"], ["main.py", "helper"], "helper", True]]})
        validate({"schema_version": 1, "cases": [c]})
        base = response(c)
        base["target"] = [{"id": "caller", "name": "caller", "location": {"file": "main.py"}}]
        base["symbols"][0]["id"] = "helper"
        edge = {"name": "helper", "kind": "CALLS", "resolved": True, "from": "caller", "to": "helper"}
        for candidate, status, correct in [(edge, "complete", True),
                (dict(edge, **{"from": "helper", "to": "caller"}), "complete", False),
                (dict(edge, to="absent"), "failed", None)]:
            with self.subTest(edge=candidate), patch("benchmark_queries.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(dict(base, edges=[candidate])).encode(), b"")):
                row = run_case(Path("sentinel"), c, 1)
                self.assertEqual(row["status"], status)
                self.assertEqual(row.get("correct"), correct)
        unresolved = dict(c, expected={"symbols": [["main.py", "helper"]], "edges": [["missing", False]],
            "endpoint_edges": [[["main.py", "caller"], None, "missing", False]]})
        validate({"schema_version": 1, "cases": [unresolved]})
        opaque = dict(edge, name="missing", resolved=False, to="unresolved:missing")
        with patch("benchmark_queries.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(dict(base, edges=[opaque])).encode(), b"")):
            self.assertTrue(run_case(Path("sentinel"), unresolved, 1)["correct"])
        bad = dict(c, expected=dict(c["expected"], endpoint_edges=[]))
        with self.assertRaisesRegex(ValueError, "contradict"):
            validate({"schema_version": 1, "cases": [bad]})

    def test_validation_rejects_path_escape_commands_leakage_and_invalid_labels(self):
        validate({"schema_version": 1, "cases": [case()]})
        for changes in [{"files": {"../bad.py": "x"}}, {"files": {".git/config": "x"}},
                        {"command": "shell"}, {"expected": {"symbols": [], "edges": [["helper", 1]]}},
                        {"target": "-x"}]:
            c = dict(case(), **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate({"schema_version": 1, "cases": [c]})
        second = dict(case(), id="second", split="holdout")
        with self.assertRaisesRegex(ValueError, "family leaks"):
            validate({"schema_version": 1, "cases": [case(), second]})

    def test_wrong_stale_truncated_partial_and_malformed_results_are_distinguished(self):
        c = case()
        base = response(c)
        for code, query, status, correct in [
            (0, base, "complete", True),
            (0, dict(base, symbols=[]), "complete", False),
            (2, dict(base, index_complete=False), "partial", None),
            (0, dict(base, index_complete=False), "failed", None),
            (0, dict(base, source_snapshot="a" * 64), "failed", None),
            (0, dict(base, omitted_count=1), "failed", None),
            (0, dict(base, omitted_count=False), "failed", None),
            (0, dict(base, edges=[{"name": "helper", "kind": "CALLS", "resolved": 1}]), "failed", None),
        ]:
            with self.subTest(query=query), patch("benchmark_queries.subprocess.run",
                    return_value=subprocess.CompletedProcess([], code, json.dumps(query).encode(), b"")) as run:
                row = run_case(Path("sentinel"), c, 1)
                self.assertEqual(row["status"], status)
                self.assertEqual(row.get("correct"), correct)
                self.assertEqual(run.call_args.args[0][1:3], ["symbols", "helper"])
        with patch("benchmark_queries.subprocess.run", side_effect=subprocess.TimeoutExpired("query", 1)):
            self.assertEqual(run_case(Path("sentinel"), c, 1)["status"], "failed")
        summary = score([{"status": "complete", "correct": True}, {"status": "partial"}])
        self.assertEqual(summary["complete_accuracy"]["value"], 1)
        self.assertEqual(summary["correct_response_rate"]["value"], .5)

    def test_exact_multisets_keep_duplicate_edges_and_unresolved_flags(self):
        c = dict(case(), command="callers", expected={"symbols": [["main.py", "helper"]],
                                                     "edges": [["helper", True], ["helper", True]]})
        query = response(c)
        query["edges"] = [{"name": "helper", "kind": "CALLS", "resolved": True}] * 2
        for edges, correct in [(query["edges"], True), (query["edges"][:1], False),
                               ([dict(query["edges"][0], resolved=False)] * 2, False)]:
            with patch("benchmark_queries.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(dict(query, edges=edges)).encode(), b"")):
                self.assertEqual(run_case(Path("sentinel"), c, 1)["correct"], correct)

    def test_cli_gates_preserve_reports_and_binary_drift_takes_precedence(self):
        for status, correct, drift, expected_exit in [("complete", True, False, 0),
                ("complete", False, False, 1), ("partial", False, False, 2), ("complete", True, True, 2)]:
            with self.subTest(status=status, drift=drift), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary, corpus, output = root / "sentinel", root / "corpus.json", root / "report.json"
                binary.write_bytes(b"owned mock; not executed")
                corpus.write_text(json.dumps({"schema_version": 1, "cases": [case()]}), encoding="utf-8")
                def fake(binary, c, timeout):
                    if drift:
                        binary.write_bytes(b"replacement")
                    return dict(c, status=status, correct=correct)
                argv = ["queries", "--binary", str(binary), "--corpus", str(corpus), "--output", str(output), "--fail-on-regression"]
                with patch("sys.argv", argv), patch("benchmark_queries.run_case", side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), expected_exit)
                report = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(report["measurement_valid"], status == "complete" and not drift)
                original = output.read_bytes()
                with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    main()
                self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
