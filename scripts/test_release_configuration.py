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

"""Release-POM policy tests.

These checks run without activating the release profile or accessing signing credentials.
"""

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


NAMESPACE = "http://maven.apache.org/POM/4.0.0"
NS = {"m": NAMESPACE}
POM = Path(__file__).resolve().parents[1] / "pom.xml"


def text(element, path):
    value = element.findtext(path, namespaces=NS)
    return value.strip() if value else ""


def plugin(profile_or_build, artifact_id):
    for candidate in profile_or_build.findall(".//m:plugin", NS):
        if text(candidate, "m:artifactId") == artifact_id:
            return candidate
    raise AssertionError(f"missing plugin {artifact_id}")


class ReleaseConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = ET.parse(POM).getroot()
        cls.properties = cls.project.find("m:properties", NS)
        cls.release = next(
            profile
            for profile in cls.project.findall("m:profiles/m:profile", NS)
            if text(profile, "m:id") == "release"
        )

    def test_central_required_metadata_is_literal(self):
        artifact_id = text(self.project, "m:artifactId")
        self.assertEqual(text(self.project, "m:groupId"), "com.revetsec")
        self.assertTrue(artifact_id)
        self.assertEqual(text(self.project, "m:packaging"), "jar")
        for path in (
            "m:version",
            "m:name",
            "m:description",
            "m:url",
            "m:licenses/m:license/m:name",
            "m:licenses/m:license/m:url",
            "m:developers/m:developer/m:name",
            "m:developers/m:developer/m:email",
            "m:developers/m:developer/m:organization",
            "m:developers/m:developer/m:organizationUrl",
            "m:scm/m:connection",
            "m:scm/m:developerConnection",
            "m:scm/m:url",
        ):
            value = text(self.project, path)
            self.assertTrue(value, path)
            self.assertNotIn("${", value, path)
        self.assertEqual(
            text(self.project, "m:scm/m:url"),
            f"https://github.com/revetsec/{artifact_id}",
        )

    def test_sources_and_javadoc_are_attached(self):
        build = self.project.find("m:build", NS)
        source = plugin(build, "maven-source-plugin")
        javadoc = plugin(build, "maven-javadoc-plugin")
        self.assertIn("jar-no-fork", [text(goal, ".") for goal in source.findall(".//m:goal", NS)])
        self.assertIn("jar", [text(goal, ".") for goal in javadoc.findall(".//m:goal", NS)])

    def test_signing_enforces_best_practices(self):
        signing = plugin(self.release, "maven-gpg-plugin")
        self.assertEqual(text(signing, "m:configuration/m:bestPractices"), "true")
        execution = next(
            item
            for item in signing.findall("m:executions/m:execution", NS)
            if text(item, "m:id") == "sign-artifacts"
        )
        self.assertEqual(text(execution, "m:phase"), "verify")
        self.assertIn("sign", [text(goal, ".") for goal in execution.findall("m:goals/m:goal", NS)])

    def test_release_build_defaults_to_local_bundle_only(self):
        self.assertEqual(text(self.properties, "m:central.skipUpload"), "true")
        central = plugin(self.release, "central-publishing-maven-plugin")
        self.assertEqual(text(central, "m:extensions"), "true")
        self.assertEqual(text(central, "m:configuration/m:publishingServerId"), "central-portal")
        self.assertEqual(text(central, "m:configuration/m:autoPublish"), "false")
        self.assertEqual(text(central, "m:configuration/m:skipUpload"), "${central.skipUpload}")

    def test_release_sbom_is_reproducible_and_runtime_focused(self):
        sbom = plugin(self.release, "cyclonedx-maven-plugin")
        execution = next(
            item
            for item in sbom.findall("m:executions/m:execution", NS)
            if text(item, "m:id") == "release-sbom"
        )
        self.assertEqual(text(execution, "m:phase"), "package")
        self.assertIn("makeBom", [text(goal, ".") for goal in execution.findall("m:goals/m:goal", NS)])
        configuration = execution.find("m:configuration", NS)
        expected = {
            "projectType": "library",
            "schemaVersion": "1.6",
            "includeBomSerialNumber": "false",
            "includeCompileScope": "false",
            "includeProvidedScope": "false",
            "includeRuntimeScope": "false",
            "includeSystemScope": "false",
            "includeTestScope": "false",
            "includeLicenseText": "false",
            "outputFormat": "json",
            "outputName": "${project.build.finalName}-cyclonedx",
        }
        for name, value in expected.items():
            self.assertEqual(text(configuration, f"m:{name}"), value, name)

    def test_release_never_depends_on_a_snapshot_core(self):
        project_version = text(self.project, "m:version")
        self.assertNotIn("${", project_version)
        if not project_version.endswith("-SNAPSHOT"):
            self.assertEqual(text(self.project, "m:scm/m:tag"), f"v{project_version}")
        core_version = text(self.properties, "m:revetsec.version")
        if core_version:
            self.assertNotIn("${", core_version)
            if not project_version.endswith("-SNAPSHOT"):
                self.assertFalse(core_version.endswith("-SNAPSHOT"))


    def test_release_evidence_workflow_is_tag_gated_and_non_publishing(self):
        repository = POM.parent
        workflow_path = repository / ".github" / "workflows" / "release-evidence.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        required = (
            "tags: ['v*']",
            "id-token: write",
            "attestations: write",
            "artifact-metadata: write",
            ".verification.verified",
            "git rev-parse HEAD",
            "-Dgpg.skip=true",
            "-Dcentral.skipUpload=true",
            "clean verify",
            "sbom-path:",
            "id: provenance",
            "id: sbom",
            "ATTESTATIONS.json",
            "outputs.attestation-id",
            "outputs.attestation-url",
        )
        for value in required:
            self.assertIn(value, workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("central.skipUpload=false", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertEqual(
            workflow.count(
                "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
            ),
            2,
        )
        for line in workflow.splitlines():
            if "uses:" not in line:
                continue
            action = line.split("uses:", 1)[1].strip().split()[0]
            revision = action.rsplit("@", 1)[-1]
            self.assertEqual(len(revision), 40, line)
            self.assertTrue(all(character in "0123456789abcdef" for character in revision), line)
        installer = repository / ".github" / "scripts" / "install-pinned-corretto-linux-x64.sh"
        installer_text = installer.read_text(encoding="utf-8")
        self.assertIn("archive_sha256=", installer_text)
        self.assertIn("sha256sum --check --strict", installer_text)


if __name__ == "__main__":
    unittest.main()

