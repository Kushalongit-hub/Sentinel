import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from benchmark_refresh import main, measure, measure_context, native_identity, summarize


class RefreshBenchmarkTests(unittest.TestCase):
    def test_context_measurement_rejects_missing_targets_provenance_and_partial_success(self):
        base = {"complete": True, "target": "helper_0", "coverage_notes": [],
                "backend": {"name": "sentinel-native"}, "source_snapshot": "a" * 64,
                "omitted_count": 0, "omitted_target_symbols": 0,
                "target_symbols": [{"name": "helper_0", "location": {"file": "module_00000.py"}}],
                "selected_items": [{"evidence": {"kind": "symbol"}}]}
        for code, context, expected in [
            (0, base, "complete"),
            (2, dict(base, complete=False), "partial"),
            (0, dict(base, complete=False), "failed"),
            (0, dict(base, target_symbols=[]), "failed"),
            (0, dict(base, source_snapshot=None), "failed"),
            (0, dict(base, source_snapshot="b" * 64), "failed"),
            (2, dict(base, source_snapshot="b" * 64, complete=False), "partial"),
            (0, dict(base, backend=None), "failed"),
            (0, dict(base, omitted_target_symbols=True), "failed"),
            (0, dict(base, selected_items=[{}] * 41), "failed"),
        ]:
            with self.subTest(context=context, code=code), patch("benchmark_refresh.subprocess.run",
                    return_value=subprocess.CompletedProcess([], code, json.dumps(context), "")) as run:
                row = measure_context(Path("sentinel"), Path("fixture"), 1, "a" * 64)
                self.assertEqual(row["status"], expected)
                self.assertEqual(row["expected_source_snapshot"], "a" * 64)
                self.assertEqual(run.call_args.args[0][1:3], ["context", "helper_0"])
        with patch("benchmark_refresh.subprocess.run", side_effect=subprocess.TimeoutExpired("context", 1)):
            self.assertEqual(measure_context(Path("sentinel"), Path("fixture"), 1, "a" * 64)["status"], "failed")

    def test_optional_context_groups_measure_edits_and_invalidate_partial_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "sentinel"
            binary.write_bytes(b"owned mock binary")
            output = root / "context.json"
            sources = []
            def context(binary, fixture, timeout, expected_snapshot):
                sources.append((fixture / "module_00000.py").read_text(encoding="utf-8"))
                actual = {path.name: native_identity(path.read_bytes().decode("utf-8"))
                          for path in fixture.glob("*.py")}
                self.assertEqual(expected_snapshot, native_identity(actual))
                return {"status": "partial" if len(sources) == 4 else "complete", "elapsed_ms": 1}
            argv = ["refresh", "--binary", str(binary), "--files", "2", "--repeats", "2",
                    "--context", "--output", str(output)]
            with patch("sys.argv", argv), patch("benchmark_refresh.measure",
                    return_value={"status": "complete", "elapsed_ms": 1}), patch(
                    "benchmark_refresh.measure_context", side_effect=context), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 2)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(report["context_measured"])
            self.assertFalse(report["measurement_valid"])
            self.assertEqual(report["summary"]["context_warm"]["complete"], 2)
            self.assertEqual(report["summary"]["context_one_file_changed"]["complete"], 1)
            self.assertEqual(sources[0], sources[1])
            self.assertIn("return 3", sources[2])
            self.assertIn("return 4", sources[3])

    def test_stale_complete_context_preserves_failed_report_and_never_scores_latency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "sentinel"
            binary.write_bytes(b"owned mock binary; not executed")
            output = root / "stale-context.json"
            stale_snapshot = native_identity({"module_00000.py": native_identity("def helper_0():\n    return 0\n")})
            stale = {"complete": True, "target": "helper_0", "coverage_notes": [],
                     "backend": {"name": "sentinel-native"}, "source_snapshot": stale_snapshot,
                     "omitted_count": 0, "omitted_target_symbols": 0,
                     "target_symbols": [{"name": "helper_0", "location": {"file": "module_00000.py"}}],
                     "selected_items": [{"evidence": {"kind": "symbol"}}]}
            argv = ["refresh", "--binary", str(binary), "--files", "1", "--repeats", "1",
                    "--context", "--output", str(output)]
            with patch("sys.argv", argv), patch("benchmark_refresh.measure",
                    return_value={"status": "complete", "elapsed_ms": 1}), patch(
                    "benchmark_refresh.subprocess.run", return_value=subprocess.CompletedProcess(
                        [], 0, json.dumps(stale), "")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 2)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(report["measurement_valid"])
            for group in ("context_warm", "context_one_file_changed"):
                self.assertIsNone(report["summary"][group]["p95_ms"])
                row = report["samples"][group][0]
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row["context"]["source_snapshot"], stale_snapshot)
                self.assertNotEqual(row["expected_source_snapshot"], stale_snapshot)
                self.assertIn("contradicts current fixture", row["error"])

    def test_partial_failed_and_counter_mismatches_never_enter_latency_percentiles(self):
        base = {"complete": True, "coverage_notes": [], "files_indexed": 3,
                "changed_files": 0, "unchanged_files": 3}
        for code, stats, expected in [
            (0, base, "complete"),
            (2, dict(base, complete=False, files_indexed=2), "partial"),
            (0, dict(base, complete=False), "failed"),
            (0, dict(base, changed_files=1), "failed"),
            (0, dict(base, files_indexed=True), "failed"),
        ]:
            with self.subTest(expected=expected), patch("benchmark_refresh.subprocess.run",
                    return_value=subprocess.CompletedProcess([], code, json.dumps(stats), "")):
                self.assertEqual(measure(Path("sentinel"), Path("fixture"), 3, 0, 1)["status"], expected)
        with patch("benchmark_refresh.subprocess.run", side_effect=subprocess.TimeoutExpired("index", 1)):
            self.assertEqual(measure(Path("sentinel"), Path("fixture"), 3, 0, 1)["status"], "failed")
        self.assertEqual(summarize([{"status": "partial", "elapsed_ms": 1}])["p95_ms"], None)
        self.assertEqual(summarize([{"status": "complete", "elapsed_ms": v} for v in [3, 1, 2]])["p95_ms"], 3)

    def test_cli_preserves_partial_reports_fixture_changes_and_refuses_overwrite(self):
        for partial, expected in [(False, 0), (True, 2)]:
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "sentinel"
                binary.write_bytes(b"owned mock binary; not executed")
                output = root / "report.json"
                seen = []
                def fake(binary, fixture, count, changed, timeout):
                    self.assertEqual(len(list(fixture.glob("*.py"))), count)
                    for path in fixture.glob("*.py"):
                        self.assertNotIn(b"\r", path.read_bytes())
                    seen.append((changed, (fixture / "module_00000.py").read_text()))
                    return {"status": "partial" if partial else "complete", "elapsed_ms": 1}
                argv = ["refresh", "--binary", str(binary), "--files", "3", "--repeats", "2", "--output", str(output)]
                with patch("sys.argv", argv), patch("benchmark_refresh.measure", side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), expected)
                report = json.loads(output.read_text())
                self.assertEqual([changed for changed, _ in seen], [3, 0, 0, 1, 1])
                self.assertIn("return 1", seen[-2][1])
                self.assertIn("return 2", seen[-1][1])
                self.assertEqual(report["measurement_valid"], not partial)
                self.assertEqual(len(report["fixture_sha256"]), 64)
                self.assertEqual(report["fixture_newlines"], "lf")
                original = output.read_bytes()
                with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    main()
                self.assertEqual(output.read_bytes(), original)


    def test_binary_drift_invalidates_and_preserves_an_otherwise_complete_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "sentinel"
            binary.write_bytes(b"original owned mock")
            output = root / "drift.json"
            def changed(*args):
                binary.write_bytes(b"replacement owned mock")
                return {"status": "complete", "elapsed_ms": 1}
            argv = ["refresh", "--binary", str(binary), "--files", "1", "--repeats", "1", "--output", str(output)]
            with patch("sys.argv", argv), patch("benchmark_refresh.measure", side_effect=changed), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 2)
            report = json.loads(output.read_text())
            self.assertFalse(report["measurement_valid"])
            self.assertNotEqual(report["binary_sha256"], report["binary_sha256_after"])
            self.assertEqual(report["summary"]["warm"]["complete"], 1)


    def test_repeated_cold_samples_use_distinct_source_roots_and_last_root_for_warm_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            binary = directory / "sentinel"
            binary.write_bytes(b"owned mock binary")
            output = directory / "repeat.json"
            calls = []
            def record(binary, root, count, changed, timeout):
                calls.append((root, changed))
                self.assertEqual(len(list(root.glob("*.py"))), count)
                return {"status": "complete", "elapsed_ms": len(calls)}
            argv = ["refresh", "--binary", str(binary), "--files", "2", "--cold-repeats", "3", "--repeats", "2", "--output", str(output)]
            with patch("sys.argv", argv), patch("benchmark_refresh.measure", side_effect=record), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)
            self.assertEqual(len({root for root, _ in calls[:3]}), 3)
            self.assertTrue(all(root == calls[2][0] for root, _ in calls[3:]))
            self.assertEqual([changed for _, changed in calls], [2, 2, 2, 0, 0, 1, 1])
            report = json.loads(output.read_text())
            self.assertEqual(report["cold_repeats"], 3)
            self.assertEqual(report["summary"]["cold"]["samples"], 3)
            self.assertEqual(report["summary"]["cold"]["p50_ms"], 2)
            self.assertEqual(report["summary"]["cold"]["p95_ms"], 3)
            self.assertTrue(all(not root.exists() for root, _ in calls))


if __name__ == "__main__":
    unittest.main()
