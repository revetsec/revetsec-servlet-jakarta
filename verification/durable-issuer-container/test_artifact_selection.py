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


"""Bad artifact identities must precede output, Docker resources or listeners."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class InputSelectionTests(unittest.TestCase):
    def invoke(self,kind,value):
        with tempfile.TemporaryDirectory(prefix="durable-issuer-selection-")as temporary:
            root=Path(temporary);files={name:root/(name+".jar")for name in ["core","adapter","store","pyranid","driver"]}
            for name,path in files.items():path.write_bytes(("private-placeholder-"+name).encode())
            archive=root/"runtime.tar.gz";archive.write_bytes(b"private-runtime");checker=root/"checker.jar";checker.write_bytes(b"private-annotation")
            for name in ["org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar","com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar","com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]:
                p=root/name;p.parent.mkdir(parents=True);p.write_bytes(b"private-compile-only")
            pg=root/"reference";(pg/"src/main/java/example/pending").mkdir(parents=True);(pg/"issuer-schema.sql").write_bytes(b"private-schema")
            for name in ["PostgresqlIssuerStore.java","IssuerPgScope.java","IssuerPgLocks.java","IssuerPgCapacity.java","IssuerPgTransactions.java"]:(pg/"src/main/java/example/pending"/name).write_bytes(b"private-source")
            command=[sys.executable,"-B",str(Path(__file__).with_name("run.py")),"--tomcat-archive",str(archive),"--checker-qual-jar",str(checker),"--java-home",str(root),"--annotations-repository",str(root),"--reference-store-source-root",str(pg),"--output",str(root/"evidence")]
            for name,path in files.items():command += ["--"+name+"-jar",str(path),"--"+name+"-sha256",value if kind==name else hashlib.sha256(path.read_bytes()).hexdigest()]
            result=subprocess.run(command,capture_output=True,text=True,timeout=5);self.assertEqual(2,result.returncode);self.assertIn("Selected "+kind.upper()+" SHA256 mismatch before resources",result.stderr);self.assertFalse((root/"evidence").exists())
    def variants(self,kind):
        for value in ["0"*64,"A"*64,"invalid"]:
            with self.subTest(kind=kind,value=value):self.invoke(kind,value)
    def test_core(self):self.variants("core")
    def test_adapter(self):self.variants("adapter")
    def test_store(self):self.variants("store")
    def test_pyranid(self):self.variants("pyranid")
    def test_driver(self):self.variants("driver")

if __name__=="__main__":unittest.main()
