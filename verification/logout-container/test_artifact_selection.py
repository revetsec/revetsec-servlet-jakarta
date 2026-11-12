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


"""Exact selected-artifact refusal occurs before output or listener creation."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ArtifactSelectionTests(unittest.TestCase):
    def test_selected_core_hash_before_resources(self):
        for supplied in ["0"*64,"A"*64,"invalid"]:
            self.assert_rejected("core",supplied,"Selected core SHA256 mismatch before instance creation")
    def test_selected_common_hash_before_resources(self):
        self.assert_rejected("common","0"*64,"Selected common SHA256 mismatch before instance creation")
    def test_selected_fixture_hash_before_resources(self):
        self.assert_rejected("fixture","0"*64,"Selected fixture SHA256 mismatch before instance creation")
    def test_reviewed_archive_before_resources(self):
        self.assert_rejected("archive",None,"Tomcat archive differs from reviewed SHA512")
    def assert_rejected(self,selected,supplied,message):
        with tempfile.TemporaryDirectory(prefix="logout-selection-") as directory:
            root=Path(directory);arguments=[]
            for kind in ["core","common","fixture"]:
                path=root/(kind+".jar");path.write_bytes(("private invalid "+kind).encode())
                arguments += ["--"+kind+"-jar",str(path),"--"+kind+"-sha256",supplied if selected==kind else hashlib.sha256(path.read_bytes()).hexdigest()]
            archive=root/"tomcat.tar.gz";archive.write_bytes(b"private invalid runtime")
            for name in ["org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar","com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar","com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]:
                path=root/name;path.parent.mkdir(parents=True);path.write_bytes(b"private placeholder")
            result=subprocess.run([sys.executable,str(Path(__file__).with_name("run.py")),*arguments,"--tomcat-archive",str(archive),"--java-home",str(root),"--annotations-repository",str(root),"--output",str(root/"evidence")],capture_output=True,text=True,timeout=5)
            self.assertEqual(2,result.returncode);self.assertIn(message,result.stderr);self.assertFalse((root/"evidence").exists())


if __name__=="__main__":unittest.main()
