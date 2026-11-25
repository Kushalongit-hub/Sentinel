import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess
import tempfile
import contextlib
import io

from benchmark import main, rate, run_case, score, validate, validate_report


class BenchmarkTests(unittest.TestCase):
    def test_cli_gate_preserves_reports_and_distinguishes_regressions_from_failures(self):
        for gate, error, expected in [(False, "fn", 0), (True, "fn", 1),
                                      (True, "fp", 1), (True, "failed", 2),
                                      (False, "failed", 2), (True, None, 0)]:
            with self.subTest(gate=gate, error=error), tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / "sentinel"
                binary.write_bytes(b"fake binary; run_case is mocked")
                output = Path(directory) / "report.json"
                argv = ["benchmark", "--binary", str(binary), "--output", str(output)]
                if gate:
                    argv.append("--fail-on-regression")
                def result(binary, case, timeout):
                    row = dict(id=case["id"], engine="rules", **{"class": case["class"]},
                               positive=case["positive"], split=case["split"], status="complete", detected=case["positive"])
                    if error == "failed":
                        row["status"] = "failed"
                    elif (error == "fn" and case["positive"]) or (error == "fp" and not case["positive"]):
                        row["detected"] = not case["positive"]
                    return row
                with patch("sys.argv", argv), patch("benchmark.run_case", side_effect=result), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), expected)
                report = json.loads(output.read_text())
                self.assertEqual(len(report["binary_sha256"]), 64)
                if error:
                    self.assertGreater(report["summary"][error], 0)

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

    def test_failure_coverage_and_positive_detection_include_all_labels(self):
        rows = [dict(status="complete", positive=True, detected=True),
                dict(status="failed", positive=True), dict(status="failed", positive=False)]
        result = score(rows)
        self.assertEqual(result["recall"]["value"], 1)
        self.assertEqual(result["positive_detection_rate"]["value"], 0.5)
        self.assertEqual(result["positive_detection_rate"]["denominator"], 2)
        self.assertEqual(result["completion_rate"]["value"], 1 / 3)
        self.assertEqual((result["failed_positive"], result["failed_negative"]), (1, 1))
        self.assertEqual(result["fn"], 0)
        self.assertEqual(result["tn"], 0)
        failed = score(rows[1:])
        self.assertIsNone(failed["precision"]["value"])
        self.assertIsNone(failed["recall"]["value"])
        self.assertEqual(failed["positive_detection_rate"]["value"], 0)
        self.assertEqual(failed["completion_rate"]["value"], 0)
        self.assertIsNone(score([])["completion_rate"]["value"])

    def test_combined_reports_keep_development_and_holdout_scores_separate(self):
        corpus = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/seed.json").read_text())
        held_family = corpus["cases"][0]["family"]
        for case in corpus["cases"]:
            if case["family"] == held_family:
                case["split"] = "holdout"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path, binary, output = root / "corpus.json", root / "sentinel", root / "report.json"
            corpus_path.write_text(json.dumps(corpus))
            binary.write_bytes(b"mock binary")
            def result(binary, case, timeout):
                return dict(id=case["id"], family=case["family"], **{"class":case["class"]},
                            engine=case.get("engine", "rules"), split=case["split"], positive=case["positive"],
                            status="complete", detected=case["positive"] if case["split"] == "development" else False)
            argv = ["benchmark", "--binary", str(binary), "--corpus", str(corpus_path),
                    "--output", str(output), "--split", "all", "--fail-on-regression"]
            with patch("sys.argv", argv), patch("benchmark.run_case", side_effect=result), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 1)
            report = json.loads(output.read_text())
            self.assertEqual(report["per_split"]["development"]["fn"], 0)
            self.assertGreater(report["per_split"]["holdout"]["fn"], 0)
            self.assertEqual(sum(group["total_cases"] for group in report["per_split"].values()), report["summary"]["total_cases"])

    def test_binary_identity_is_bound_before_scans_and_changes_invalidate_saved_report(self):
        import hashlib
        corpus = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/seed.json").read_text())
        for change in (None, "replace", "remove"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                corpus_path, binary, output = root / "corpus.json", root / "sentinel", root / "report.json"
                corpus_path.write_text(json.dumps(corpus))
                binary.write_bytes(b"original binary")
                def result(binary, case, timeout):
                    if change == "replace":
                        binary.write_bytes(b"replacement binary")
                    elif change == "remove":
                        binary.unlink(missing_ok=True)
                    return dict(id=case["id"], **{"class":case["class"]}, engine=case.get("engine", "rules"),
                                split=case["split"], positive=case["positive"], status="complete", detected=case["positive"])
                argv = ["benchmark", "--binary", str(binary), "--corpus", str(corpus_path), "--output", str(output)]
                with patch("sys.argv", argv), patch("benchmark.run_case", side_effect=result), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), 0 if change is None else 2)
                report = json.loads(output.read_text())
                self.assertEqual(report["binary_sha256"], hashlib.sha256(b"original binary").hexdigest())
                self.assertEqual(report["measurement_valid"], change is None)
                self.assertEqual(bool(report["measurement_errors"]), change is not None)
                self.assertEqual(report["summary"]["failed"], 0)
                if change == "remove":
                    self.assertIsNone(report["binary_sha256_after"])
                elif change == "replace":
                    self.assertNotEqual(report["binary_sha256"], report["binary_sha256_after"])
                else:
                    self.assertEqual(report["binary_sha256"], report["binary_sha256_after"])

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
