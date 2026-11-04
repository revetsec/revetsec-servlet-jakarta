#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Guard calibration against survivors, wrong oracles and setup/cleanup false positives."""
import copy
import importlib.util
import tempfile
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch, call
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("m12_calibration", HERE / "calibrate.py")
CALIBRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CALIBRATION)
RUN_SPEC = importlib.util.spec_from_file_location("m12_runner", HERE / "run.py")
RUNNER = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(RUNNER)


def failed_result():
    return dict(success=False, failureKind="assertion", failedCheck="expected-check", runtimeReady=True,
                ownedProcessStopped=True, privateInstanceRemoved=True, sourceInputsStable=True)


class CalibrationTests(unittest.TestCase):
    def test_only_the_expected_ready_clean_assertion_counts(self):
        self.assertEqual("detected", CALIBRATION.classify(1, failed_result(), "expected-check"))

    def test_wrong_assertion_does_not_count(self):
        self.assertEqual("unexpected-failure", CALIBRATION.classify(1, failed_result(), "other-check"))

    def test_each_readiness_cleanup_and_source_guard_is_required(self):
        for field in ["runtimeReady", "ownedProcessStopped", "privateInstanceRemoved", "sourceInputsStable"]:
            for value in [False, None]:
                with self.subTest(field=field, value=value):
                    result = failed_result(); result[field] = value
                    self.assertEqual("unexpected-failure", CALIBRATION.classify(1, result, "expected-check"))

    def test_setup_and_timeout_are_not_detection(self):
        self.assertEqual("setup-failure", CALIBRATION.classify(1, None, "expected-check"))
        self.assertEqual("setup-failure", CALIBRATION.classify(-1, None, "expected-check"))
        result = failed_result(); result["failureKind"] = "infrastructure"
        self.assertEqual("unexpected-failure", CALIBRATION.classify(1, result, "expected-check"))

    def test_survivor_and_inconsistent_exit_do_not_count(self):
        self.assertEqual("survived", CALIBRATION.classify(0, dict(success=True), "expected-check"))
        self.assertEqual("unexpected-failure", CALIBRATION.classify(2, failed_result(), "expected-check"))
        self.assertEqual("unexpected-failure", CALIBRATION.classify(0, failed_result(), "expected-check"))

    def test_positive_requires_success_ready_cleanup_and_stable_source(self):
        result = failed_result(); result["success"] = True
        self.assertTrue(CALIBRATION.positive(0, result))
        self.assertFalse(CALIBRATION.positive(1, result))
        for field in ["success", "runtimeReady", "ownedProcessStopped", "privateInstanceRemoved", "sourceInputsStable"]:
            changed = copy.copy(result); changed[field] = False
            self.assertFalse(CALIBRATION.positive(0, changed))

    def test_failure_receipts_keep_fixed_check_ids_and_redact_arbitrary_text(self):
        self.assertEqual("oauth-redirect-policy", RUNNER.failure_details(AssertionError("oauth-redirect-policy"))["failedCheck"])
        for failure in [RuntimeError("credential=private"), AssertionError("body\ncredential=private"), AssertionError("opaquecredential"), AssertionError()]:
            result = RUNNER.failure_details(failure)
            self.assertEqual("infrastructure", result["failureKind"])
            self.assertIsNone(result["failedCheck"])
            self.assertNotIn("private", str(result))

    def test_all_plants_are_unique_body_changes_with_named_oracles(self):
        repo = HERE.parents[1]
        for namespace in ["jakarta", "javax"]:
            cases = CALIBRATION.cases(namespace)
            self.assertEqual(8, len(cases)); self.assertEqual(8, len({case["id"] for case in cases}))
            self.assertEqual(8, len({case["expected"] for case in cases}))
            if not (repo / ("src/main/java/com/revetsec/servlet/" + namespace)).is_dir(): continue
            for case in cases:
                source = (repo / case["target"]).read_text()
                self.assertEqual(1, source.count(case["old"]), case["id"])
                self.assertNotEqual(source, source.replace(case["old"], case["new"]))
                self.assertNotIn("\npackage ", case["new"])

    def test_both_entry_points_refuse_optimized_python(self):
        for name in ["run.py", "calibrate.py"]:
            normal = subprocess.run([sys.executable, str(HERE/name), "--help"], capture_output=True, text=True)
            self.assertEqual(0, normal.returncode)
            optimized = subprocess.run([sys.executable, "-O", str(HERE/name), "--help"], capture_output=True, text=True)
            self.assertNotEqual(0, optimized.returncode)
            self.assertIn("Python optimization disables qualification assertions", optimized.stderr)

    def test_timeout_and_cancellation_stop_the_owned_process_group(self):
        args = SimpleNamespace(tomcat_archive=Path("runtime"), core_jar=Path("core"), java_home=Path("jdk"))
        for failure in [subprocess.TimeoutExpired("fixture", 180), CALIBRATION.CalibrationInterrupted()]:
            process = Mock(pid=123); process.communicate.side_effect = [failure, (b"", b"")]
            with patch.object(CALIBRATION.subprocess, "Popen", return_value=process), patch.object(CALIBRATION.os, "killpg") as stopped:
                if isinstance(failure, subprocess.TimeoutExpired):
                    self.assertEqual((-1, None), CALIBRATION.workload(Path("source"), Path("adapter"), args, Path("output"), Path("work")))
                else:
                    with self.assertRaises(CALIBRATION.CalibrationInterrupted):
                        CALIBRATION.workload(Path("source"), Path("adapter"), args, Path("output"), Path("work"))
                stopped.assert_called_once_with(123, CALIBRATION.signal.SIGTERM)
        self.assertFalse(issubclass(CALIBRATION.CalibrationInterrupted, Exception))

    def test_stubborn_owned_group_gets_bounded_kill_fallback(self):
        process = Mock(pid=123); process.communicate.side_effect = [subprocess.TimeoutExpired("fixture", 15), (b"", b"")]
        with patch.object(CALIBRATION.os, "killpg") as stopped:
            CALIBRATION.stop_group(process)
            self.assertEqual([call(123, CALIBRATION.signal.SIGTERM), call(123, CALIBRATION.signal.SIGKILL)], stopped.call_args_list)
        with self.assertRaises(CALIBRATION.CalibrationInterrupted):
            CALIBRATION.interrupted(CALIBRATION.signal.SIGTERM, None)

    def test_snapshot_and_digest_detect_source_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/"snapshot"
            repo = HERE.parents[1]
            CALIBRATION.snapshot(repo, target)
            before = CALIBRATION.source_inputs(repo)
            self.assertEqual(before, CALIBRATION.source_inputs(target))
            sample = target / CALIBRATION.cases("jakarta" if "jakarta" in str(repo) else "javax")[0]["target"]
            sample.write_text(sample.read_text()+"\n")
            self.assertNotEqual(before, CALIBRATION.source_inputs(target))


if __name__ == "__main__":
    unittest.main()
