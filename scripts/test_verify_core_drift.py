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

"""Self-tests for verify-core-drift.py, and for the CI workflow that runs it.

Run with: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("verify_core_drift", SCRIPT_DIRECTORY / "verify-core-drift.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

COMMIT = "a" * 40
POM_OPEN = '<project xmlns="http://maven.apache.org/POM/4.0.0">'
CORE_POM = POM_OPEN + """
<groupId>com.revetsec</groupId><artifactId>revetsec</artifactId><version>1.0.0-SNAPSHOT</version>
</project>
"""
ADAPTER_POM = POM_OPEN + """
<groupId>com.revetsec</groupId><artifactId>revetsec-example</artifactId><version>1.0.0-SNAPSHOT</version>
<properties><revetsec.version>1.0.0-SNAPSHOT</revetsec.version></properties>
<dependencies><dependency><groupId>com.revetsec</groupId><artifactId>revetsec</artifactId>
<version>${revetsec.version}</version><scope>provided</scope></dependency></dependencies>
</project>
"""
CLAIMS_LINT_SOURCE = "/* header */\n\npackage {package};\n\nfinal class ClaimsLintTests {{\n}}\n"
SHARED_INDEX = b"module:java.base\njava.lang\n"
FRAMEWORK_INDEX = b"com.example\n"


def manifest(*entries):
    return json.dumps({"description": "test", "indexes": list(entries)}, indent=2) + "\n"


def index_entry(path, content):
    return {"path": path, "url": "https://example.com/" + path.split("/")[0] + "/",
            "sha256": hashlib.sha256(content).hexdigest()}


class CoreDriftTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.core = Path(temporary.name) / "core"
        self.adapter = Path(temporary.name) / "adapter"
        self.write_core_and_adapter()
        self.read_commit = patch.object(VERIFIER, "read_commit", return_value=COMMIT).start()
        self.addCleanup(patch.stopall)

    def write(self, root, relative_path, content):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    def write_core_and_adapter(self):
        for root, pom, package, test_directory in (
                (self.core, CORE_POM, "com.revetsec", "src/test/java/com/revetsec"),
                (self.adapter, ADAPTER_POM, "com.revetsec.example", "src/test/java/com/revetsec/example")):
            self.write(root, "pom.xml", pom)
            for name in VERIFIER.VERBATIM_FILES:
                self.write(root, name, f"The shared {name}.\n")
            self.write(root, f"{test_directory}/ClaimsLintTests.java", CLAIMS_LINT_SOURCE.format(package=package))
            self.write(root, "src/test/resources/contract-fixtures/claims/README.md", "Seeded claims.\n")
            self.write(root, "src/test/resources/contract-fixtures/claims/docs/guide.md", "More seeded claims.\n")
            self.write(root, "src/main/javadoc/links/java-26/element-list", SHARED_INDEX)
        shared_entry = index_entry("java-26/element-list", SHARED_INDEX)
        self.write(self.core, "src/main/javadoc/links/manifest.json", manifest(shared_entry))
        self.write(self.adapter, "src/main/javadoc/links/example-1.0/element-list", FRAMEWORK_INDEX)
        self.write(self.adapter, "src/main/javadoc/links/manifest.json",
                   manifest(shared_entry, index_entry("example-1.0/element-list", FRAMEWORK_INDEX)))

    def problems(self, expected_commit=None):
        problems, _ = VERIFIER.verify(self.core, self.adapter, expected_commit)
        return problems

    def assert_single_problem(self, fragment, expected_commit=None):
        problems = self.problems(expected_commit)
        self.assertEqual(1, len(problems), problems)
        self.assertIn(fragment, problems[0])

    def test_identical_copies_pass(self):
        self.assertEqual([], self.problems())
        self.assertEqual([], self.problems(COMMIT))

    def test_rejects_the_placeholder_pin(self):
        self.assert_single_problem("40-zero placeholder", "0" * 40)
        self.read_commit.assert_not_called()

    def test_rejects_mutable_or_abbreviated_pins(self):
        for selector in ("main", "v1.0.0", COMMIT[:7], COMMIT.upper(), ""):
            with self.subTest(selector=selector):
                self.assert_single_problem("not a full 40-character lowercase commit SHA", selector)
        self.read_commit.assert_not_called()

    def test_rejects_a_different_checkout(self):
        self.read_commit.return_value = "b" * 40
        self.assert_single_problem("Core checkout is at " + "b" * 40, COMMIT)

    def test_rejects_wrong_core_coordinates(self):
        self.write(self.core, "pom.xml", CORE_POM.replace("<artifactId>revetsec<", "<artifactId>other<"))
        self.assert_single_problem("builds com.revetsec:other")

    def test_rejects_a_version_mismatch(self):
        self.write(self.core, "pom.xml", CORE_POM.replace("1.0.0-SNAPSHOT", "1.1.0-SNAPSHOT"))
        self.assert_single_problem("Core checkout is version 1.1.0-SNAPSHOT")

    def test_rejects_an_unresolved_core_version(self):
        self.write(self.core, "pom.xml", CORE_POM.replace("1.0.0-SNAPSHOT", "${revision}"))
        with self.assertRaisesRegex(VERIFIER.DriftError, "literal"):
            self.problems()

    def test_rejects_a_dependency_that_bypasses_the_declared_version(self):
        self.write(self.adapter, "pom.xml", ADAPTER_POM.replace("${revetsec.version}", "1.0.0-SNAPSHOT"))
        self.assert_single_problem("must use the version ${revetsec.version}")

    def test_rejects_a_core_dependency_that_is_not_provided(self):
        self.write(self.adapter, "pom.xml", ADAPTER_POM.replace("<scope>provided</scope>", "<scope>compile</scope>"))
        self.assert_single_problem("must have provided scope")

    def test_rejects_drift_in_each_verbatim_file(self):
        for name in VERIFIER.VERBATIM_FILES:
            with self.subTest(name=name):
                self.write(self.adapter, name, f"A locally edited {name}.\n")
                self.assert_single_problem(f"{name} differs from core")
                self.write(self.adapter, name, f"The shared {name}.\n")

    def test_shows_a_diff_for_drifted_text(self):
        self.write(self.adapter, "SECURITY.md", "The shared SECURITY.md.\nAn extra line.\n")
        problem = self.problems()[0]
        self.assertIn("+An extra line.", problem)
        self.assertIn("--- core/SECURITY.md", problem)

    def test_rejects_a_missing_verbatim_file(self):
        (self.adapter / "NAMING_CONVENTIONS.md").unlink()
        self.assert_single_problem("The adapter has no NAMING_CONVENTIONS.md")

    def test_claims_lint_copy_may_differ_only_in_its_package(self):
        self.write(self.adapter, "src/test/java/com/revetsec/example/ClaimsLintTests.java",
                   CLAIMS_LINT_SOURCE.format(package="com.revetsec.example").replace("}", "\tstatic int x;\n}"))
        self.assert_single_problem("ClaimsLintTests.java (package declaration ignored) differs from core")

    def test_rejects_claims_fixture_drift(self):
        self.write(self.adapter, "src/test/resources/contract-fixtures/claims/docs/guide.md", "Edited.\n")
        self.assert_single_problem("contract-fixtures/claims/docs/guide.md differs from core")
        self.write(self.adapter, "src/test/resources/contract-fixtures/claims/docs/guide.md", "More seeded claims.\n")
        self.write(self.core, "src/test/resources/contract-fixtures/claims/extra.md", "New in core.\n")
        self.assert_single_problem("claims/extra.md is in core but missing from the adapter")

    def test_rejects_a_changed_shared_javadoc_index(self):
        changed = b"module:java.base\njava.lang\njava.util\n"
        self.write(self.adapter, "src/main/javadoc/links/java-26/element-list", changed)
        problems = self.problems()
        self.assertTrue(any("java-26/element-list differs from core" in problem for problem in problems), problems)
        self.assertTrue(any("does not match the SHA-256" in problem for problem in problems), problems)

    def test_rejects_a_changed_shared_manifest_entry(self):
        entries = json.loads((self.adapter / "src/main/javadoc/links/manifest.json").read_text())["indexes"]
        entries[0]["url"] = "https://example.org/other/"
        self.write(self.adapter, "src/main/javadoc/links/manifest.json", manifest(*entries))
        self.assert_single_problem("manifest entry for java-26/element-list differs from core's")

    def test_rejects_a_missing_shared_manifest_entry(self):
        self.write(self.adapter, "src/main/javadoc/links/manifest.json",
                   manifest(index_entry("example-1.0/element-list", FRAMEWORK_INDEX)))
        self.assert_single_problem("lacks core's index java-26/element-list")

    def test_rejects_a_framework_index_that_does_not_match_its_checksum(self):
        self.write(self.adapter, "src/main/javadoc/links/example-1.0/element-list", b"com.example.changed\n")
        self.assert_single_problem("example-1.0/element-list does not match the SHA-256")

    def test_main_reports_problems_and_exit_status(self):
        self.write(self.adapter, "LICENSE", "Different.\n")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = VERIFIER.main(["--core-directory", str(self.core), "--adapter-directory", str(self.adapter)])
        self.assertEqual(1, status)
        self.assertIn("LICENSE differs from core", errors.getvalue())

        self.write(self.adapter, "LICENSE", "The shared LICENSE.\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = VERIFIER.main(["--core-directory", str(self.core), "--adapter-directory", str(self.adapter),
                                    "--expected-commit", COMMIT])
        self.assertEqual(0, status)
        self.assertIn("No drift from Revetsec core com.revetsec:revetsec:1.0.0-SNAPSHOT at " + COMMIT, output.getvalue())


class WorkflowTests(unittest.TestCase):
    """The CI workflow must build against exactly the pinned core, and fail loudly while the pin is unset."""

    def setUp(self):
        self.workflow = (SCRIPT_DIRECTORY.parent / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def jobs(self):
        body = self.workflow[self.workflow.index("\njobs:\n"):]
        names = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):$", body))
        return {match.group(1): body[match.end():names[index + 1].start() if index + 1 < len(names) else len(body)]
                for index, match in enumerate(names)}

    def test_pin_is_one_literal_full_sha(self):
        pins = re.findall(r"(?m)^  REVETSEC_CORE_SHA: '([0-9a-f]{40})'$", self.workflow)
        self.assertEqual(1, len(pins), "REVETSEC_CORE_SHA must be set once, at workflow level, to a quoted SHA")
        self.assertEqual(1, self.workflow.count("REVETSEC_CORE_SHA:"))

    def test_every_core_checkout_uses_the_pin_after_validating_it(self):
        core_jobs = 0
        for name, job in self.jobs().items():
            if "repository: revetsec/revetsec" not in job:
                continue
            core_jobs += 1
            with self.subTest(job=name):
                self.assertEqual(1, job.count("repository: revetsec/revetsec"))
                self.assertIn("ref: ${{ env.REVETSEC_CORE_SHA }}", job)
                self.assertIn(r'"$REVETSEC_CORE_SHA" =~ ^0{40}$', job)
                self.assertLess(job.index("name: Validate the core pin"), job.index("repository: revetsec/revetsec"))
                if "-f core/pom.xml" in job:
                    self.assertLess(job.index("rm -rf ~/.m2/repository/com/revetsec"), job.index("-f core/pom.xml"))
                    self.assertLess(job.index("-f core/pom.xml"), job.index("-f adapter/pom.xml"))
        self.assertEqual(3, core_jobs)

    def test_core_is_installed_without_tests_or_javadoc(self):
        installs = re.findall(r"mvn [^\n]*-f core/pom\.xml[^\n]*", self.workflow)
        self.assertEqual(2, len(installs))
        for install in installs:
            self.assertIn("-DskipTests", install)
            self.assertIn("-Dmaven.javadoc.skip=true", install)
            self.assertTrue(install.endswith(" install"), install)

    def test_never_overrides_the_declared_core_version(self):
        self.assertNotIn("-Drevetsec.version", self.workflow)

    def test_drift_check_runs_against_the_pin(self):
        self.assertIn('--expected-commit "$REVETSEC_CORE_SHA"', self.jobs()["drift"])
        self.assertIn("python3 -m unittest discover -s adapter/scripts", self.jobs()["drift"])

    def test_builds_on_every_supported_jdk(self):
        self.assertIn("jdk: ['17', '21', '25', '27']", self.jobs()["test"])

    def test_every_action_is_pinned_to_a_commit(self):
        uses = re.findall(r"uses: ([^\s]+)", self.workflow)
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
