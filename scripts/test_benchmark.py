import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

from benchmark import rate, run_case, score, validate, validate_report


class BenchmarkTests(unittest.TestCase):
    def test_report_rejects_contradictory_exit_and_malformed_evidence(self):
        good = dict(outcome="Complete", findings=[], files_scanned=1, coverage_notes=[],
                    scanner_results=[dict(name="bundled", outcome="Completed")])
        validate_report(good, 0)
        bad_reports = [dict(good, files_scanned=True), dict(good, findings={}),
                       dict(good, scanner_results=[]), dict(good, coverage_notes="partial"),
                       dict(good, scanner_results=[dict(outcome="Failed")]),
                       dict(good, findings=[dict(title="rule", severity="High", line=0)])]
        for report in bad_reports:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report(report, 0)
        with self.assertRaises(ValueError):
            validate_report(good, 2)

    def test_fixture_rejects_portable_aliases_reserved_state_and_byte_overflow(self):
        corpus = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/seed.json").read_text())
        for files in ({"CON.py": "pass"}, {"a.py.": "pass"}, {"A.py": "pass", "a.py": "pass"},
                      {"a.py": "pass", "a.py/b.py": "pass"}, {".sentinel.db": "pass"},
                      {".git/config": "pass"}, {"main.py": "x" * (1024 * 1024 + 1)}):
            changed = copy.deepcopy(corpus)
            changed["cases"][0]["files"] = files
            with self.subTest(paths=list(files)), self.assertRaises(ValueError):
                validate(changed)
    def test_incomplete_and_timeout_are_never_scored_as_safe(self):
        case = dict(id="failure", family="failure", **{"class": "tls"}, split="development",
                    positive=False, rules=["tls"], files={"main.py": "pass\n"})
        incomplete = subprocess.CompletedProcess([], 2, json.dumps({"outcome": "Incomplete"}).encode())
        with patch("benchmark.subprocess.run", return_value=incomplete):
            row = run_case(Path("sentinel"), case, 1)
        self.assertEqual(score([row])["failed"], 1)
        self.assertEqual(score([row])["tn"], 0)
        with patch("benchmark.subprocess.run", side_effect=subprocess.TimeoutExpired("sentinel", 1)):
            row = run_case(Path("sentinel"), case, 1)
        self.assertEqual(score([row])["failed"], 1)

    def test_confusion_matrix_and_failures(self):
        rows = [dict(status="complete", positive=truth, detected=found)
                for truth, found in ((True, True), (True, False), (False, True), (False, False))]
        rows.append(dict(status="failed", positive=True))
        result = score(rows)
        self.assertEqual([result[k] for k in ("tp", "fp", "tn", "fn", "failed")], [1] * 5)
        self.assertEqual(result["recall"]["value"], 0.5)
        self.assertEqual(result["complete_cases"], 4)
        self.assertIsNone(rate(0, 0)["value"])
        self.assertLess(rate(1, 1)["wilson_95"][0], 1)

    def test_graph_report_requires_complete_trace_and_entrypoint(self):
        corpus = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/flows.json").read_text())
        validate(corpus)
        case = corpus["cases"][0]
        payload = {"taint": {"complete": False}, "report": {"outcome": "Complete", "findings": [], "files_scanned": 1, "coverage_notes": []}}
        with patch("benchmark.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload).encode())):
            row = run_case(Path("sentinel"), case, 1)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(score([row])["fn"], 0)
        case["entrypoint"] = "../outside.py"
        with self.assertRaises(ValueError):
            validate(corpus)

    def test_corpus_rejects_leakage_and_escaping_paths(self):
        corpus = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/seed.json").read_text())
        validate(corpus)
        changed = copy.deepcopy(corpus)
        changed["cases"][1]["split"] = "holdout"
        with self.assertRaises(ValueError):
            validate(changed)
        for name in ("../escape.py", "C:/escape.py", "a\\escape.py", "/escape.py"):
            changed = copy.deepcopy(corpus)
            changed["cases"][0]["files"] = {name: "pass"}
            with self.assertRaises(ValueError):
                validate(changed)


if __name__ == "__main__":
    unittest.main()
