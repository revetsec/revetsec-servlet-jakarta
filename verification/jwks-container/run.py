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

"""Qualify standalone JWKS HTTP behavior in a checksum-pinned, private loopback Tomcat."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time


def digest(path, algorithm="sha256"):
    return hashlib.new(algorithm, Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tomcat-archive", required=True, type=Path)
    parser.add_argument("--core-jar", required=True, type=Path)
    parser.add_argument("--adapter-jar", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    runtime = repo / "verification/m12-container/runtime.json"
    pins = json.loads(runtime.read_text())
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        raise SystemExit("Tomcat archive does not match the reviewed runtime pin")
    certificates = repo.parent / "revetsec/src/test/resources/fixtures/jwks"
    inputs = [runtime, Path(__file__), fixture / "JwksServlet.java", repo / "pom.xml",
              *sorted((repo / "src/main/java").rglob("*.java")),
              certificates / "publisher-leaf.pem", certificates / "publisher-root.pem"]
    sources = {str(path): digest(path) for path in inputs}
    receipt = {"success": False, "ownedProcessStopped": False, "checks": [], "sourceInputs": sources,
               "runtime": pins["version"], "archiveSha512": pins["archiveSha512"],
               "coreJarSha256": digest(args.core_jar), "adapterJarSha256": digest(args.adapter_jar)}
    checks = receipt["checks"]
    process = None
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-jwks-tomcat-") as temporary:
            root = Path(temporary)
            with tarfile.open(args.tomcat_archive) as archive:
                for member in archive.getmembers():
                    if not (root / member.name).resolve().is_relative_to(root.resolve()) or member.issym() or member.islnk():
                        raise RuntimeError("Unsafe runtime archive entry")
                archive.extractall(root, filter="data")
            home = root / ("apache-tomcat-" + pins["version"])
            base = root / "instance"
            for directory in ["conf", "logs", "temp", "work", "webapps/ROOT/WEB-INF/classes", "webapps/ROOT/WEB-INF/lib"]:
                (base / directory).mkdir(parents=True)
            classes = base / "webapps/ROOT/WEB-INF/classes"
            libraries = base / "webapps/ROOT/WEB-INF/lib"
            shutil.copyfile(home / "conf/web.xml", base / "conf/web.xml")
            shutil.copyfile(args.core_jar, libraries / "core.jar")
            shutil.copyfile(args.adapter_jar, libraries / "adapter.jar")
            assert digest(libraries / "core.jar") == receipt["coreJarSha256"]
            assert digest(libraries / "adapter.jar") == receipt["adapterJarSha256"]
            for name in ["publisher-leaf.pem", "publisher-root.pem"]:
                shutil.copyfile(certificates / name, classes / name)
            subprocess.run([str(args.java_home / "bin/javac"), "--release", "17", "-d", str(classes), "-cp",
                            os.pathsep.join(map(str, [args.core_jar, args.adapter_jar, home / "lib/servlet-api.jar"])),
                            str(fixture / "JwksServlet.java")], check=True, capture_output=True, text=True)
            checks.append("public-certificate-rs384-fixture-compiled-release17")
            (base / "webapps/ROOT/WEB-INF/web.xml").write_text('<web-app><servlet><servlet-name>jwks</servlet-name><servlet-class>example.JwksServlet</servlet-class></servlet><servlet-mapping><servlet-name>jwks</servlet-name><url-pattern>/jwks</url-pattern></servlet-mapping></web-app>')
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            (base / "conf/server.xml").write_text(f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}" protocol="HTTP/1.1" connectionTimeout="2000" maxHttpRequestHeaderSize="16384" maxHeaderCount="128" maxConnections="16" maxThreads="4"/><Engine name="fixture" defaultHost="localhost"><Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/></Engine></Service></Server>')
            environment = dict(os.environ)
            environment.pop("JAVA_TOOL_OPTIONS", None)
            environment.pop("JDK_JAVA_OPTIONS", None)
            with (args.output / "runtime.log").open("wb") as log:
                process = subprocess.Popen([str(args.java_home / "bin/java"), "-Djava.awt.headless=true",
                    "-Dcatalina.home=" + str(home), "-Dcatalina.base=" + str(base), "-cp",
                    os.pathsep.join(map(str, [home / "bin/bootstrap.jar", home / "bin/tomcat-juli.jar"])),
                    "org.apache.catalina.startup.Bootstrap", "start"], stdout=log, stderr=log, env=environment)

                def request(method, headers=()):
                    if method == "HEAD":
                        # A raw read detects illegal bytes that HTTP clients intentionally hide for HEAD.
                        lines = ["HEAD /jwks HTTP/1.1", f"Host: 127.0.0.1:{port}", "Connection: close"]
                        lines.extend(name + ": " + value for name, value in headers)
                        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                            connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
                            raw = bytearray()
                            while True:
                                chunk = connection.recv(65536)
                                if not chunk:
                                    break
                                raw.extend(chunk)
                                assert len(raw) <= 278528
                        block, separator, body = bytes(raw).partition(b"\r\n\r\n")
                        assert separator, "Missing HEAD response header boundary"
                        fields = block.decode("iso-8859-1").split("\r\n")
                        status = int(fields.pop(0).split(" ")[1])
                        return status, {name.lower(): value.strip() for name, value in
                                        (line.split(":", 1) for line in fields)}, body
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                    try:
                        connection.putrequest(method, "/jwks")
                        for name, value in headers:
                            connection.putheader(name, value)
                        connection.endheaders()
                        response = connection.getresponse()
                        body = response.read(262145)
                        assert len(body) <= 262144
                        fields = response.getheaders()
                        return response.status, {name.lower(): value for name, value in fields}, body
                    finally:
                        connection.close()

                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("Tomcat exited before readiness")
                    try:
                        get = request("GET")
                        if get[0] == 200:
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Bounded Tomcat readiness timeout")
                    time.sleep(0.1)
                key = json.loads(get[2])["keys"][0]
                assert key["alg"] == "RS384" and key["kid"] == "epic-prod" and key["kty"] == "RSA"
                assert len(key["x5c"]) == 2 and not any(name in key for name in ["d", "p", "q"])
                leaf = base64.b64decode(key["x5c"][0])
                for member, algorithm in [("x5t", "sha1"), ("x5t#S256", "sha256")]:
                    assert key[member] == base64.urlsafe_b64encode(hashlib.new(algorithm, leaf).digest()).rstrip(b"=").decode("ascii")
                assert get[1]["content-type"] == "application/jwk-set+json" and get[1]["content-length"] == str(len(get[2]))
                checks.append("actual-get-rs384-chain-thumbprints-public-only-and-content-length")
                head = request("HEAD")
                assert head[0] == 200 and head[2] == b""
                for name in ["content-type", "content-length", "etag", "cache-control"]:
                    assert head[1][name] == get[1][name], name
                checks.append("actual-head-bodyless-with-get-headers-and-length")
                for method in ["GET", "HEAD"]:
                    unchanged = request(method, [("If-None-Match", '"old"'), ("iF-NoNe-MaTcH", "W/" + get[1]["etag"])])
                    assert unchanged[0] == 304 and unchanged[2] == b""
                    assert unchanged[1]["etag"] == get[1]["etag"] and unchanged[1]["cache-control"] == get[1]["cache-control"]
                    assert "content-length" not in unchanged[1] or unchanged[1]["content-length"] == str(len(get[2]))
                checks.append("actual-get-head-304-repeated-mixed-case-conditional-fields")
                rejected = request("GET", [("If-None-Match", "x" * 4096), ("IF-NONE-MATCH", "y" * 4096)])
                assert rejected[0] == 400 and rejected[2] == b"" and rejected[1]["cache-control"] == "no-store"
                unsupported = request("POST")
                assert unsupported[0] == 405 and unsupported[1]["allow"] == "GET, HEAD" and unsupported[2] == b""
                checks.append("actual-bounded-conditional-header-400-and-method-405")
                receipt["success"] = True
    except Exception as failure:
        receipt["failure"] = str(failure)[:4000]
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            receipt["ownedProcessStopped"] = process.poll() is not None
        if sources != {str(path): digest(path) for path in inputs}:
            receipt["success"] = False
            receipt["failure"] = "Source changed during qualification"
        (args.output / "RESULT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"success": receipt["success"], "checks": len(checks), "ownedProcessStopped": receipt["ownedProcessStopped"]}))
    if not receipt["success"] or not receipt["ownedProcessStopped"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
