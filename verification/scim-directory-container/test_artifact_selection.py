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


"""Input identity failures must occur before any private instance/output is created."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ArtifactSelectionTests(unittest.TestCase):
    def test_selected_core_requires_exact_lowercase_sha256_before_resources(self):
        for supplied in ["0"*64,"A"*64,"invalid"]:
            with self.subTest(supplied=supplied),tempfile.TemporaryDirectory(prefix="scim-directory-selection-") as directory:
                root=Path(directory);core=root/"core.jar";core.write_bytes(b"private invalid artifact")
                archive=root/"runtime.tar.gz";archive.write_bytes(b"private invalid runtime")
                for name in ["org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar","com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar","com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]:
                    jar=root/name;jar.parent.mkdir(parents=True);jar.write_bytes(b"private placeholder")
                result=self.invoke(root,core,archive,supplied)
                self.assertEqual(2,result.returncode)
                self.assertIn("Selected core SHA256 mismatch before instance creation",result.stderr)
                self.assertFalse((root/"evidence").exists())

    def test_runtime_requires_reviewed_archive_identity_before_resources(self):
        with tempfile.TemporaryDirectory(prefix="scim-directory-selection-") as directory:
            root=Path(directory);core=root/"core.jar";core.write_bytes(b"private invalid artifact")
            archive=root/"runtime.tar.gz";archive.write_bytes(b"private invalid runtime")
            for name in ["org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar","com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar","com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]:
                jar=root/name;jar.parent.mkdir(parents=True);jar.write_bytes(b"private placeholder")
            result=self.invoke(root,core,archive,hashlib.sha256(core.read_bytes()).hexdigest())
            self.assertEqual(2,result.returncode)
            self.assertIn("Tomcat archive differs from reviewed SHA512",result.stderr)
            self.assertFalse((root/"evidence").exists())

    def test_selected_adapter_requires_exact_sha256_before_resources(self):
        with tempfile.TemporaryDirectory(prefix="scim-directory-selection-") as directory:
            root=Path(directory);core=root/"core.jar";core.write_bytes(b"private artifact")
            archive=root/"runtime.tar.gz";archive.write_bytes(b"private runtime")
            for name in ["org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar","com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar","com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]:
                jar=root/name;jar.parent.mkdir(parents=True);jar.write_bytes(b"private placeholder")
            result=self.invoke(root,core,archive,hashlib.sha256(core.read_bytes()).hexdigest(),"0"*64)
            self.assertEqual(2,result.returncode)
            self.assertIn("Selected adapter SHA256 mismatch before instance creation",result.stderr)
            self.assertFalse((root/"evidence").exists())

    @staticmethod
    def invoke(root,core,archive,selected,adapter_selected=None):
        adapter=root/"adapter.jar";adapter.write_bytes(b"private adapter placeholder")
        return subprocess.run([sys.executable,str(Path(__file__).with_name("run.py")),"--tomcat-archive",str(archive),
            "--core-jar",str(core),"--core-sha256",selected,"--adapter-jar",str(adapter),"--adapter-sha256",adapter_selected or hashlib.sha256(adapter.read_bytes()).hexdigest(),"--java-home",str(root),"--annotations-repository",str(root),
            "--output",str(root/"evidence")],capture_output=True,text=True,timeout=5)


if __name__=="__main__":unittest.main()
