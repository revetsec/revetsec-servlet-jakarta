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

"""Compile the paired cookbook servlet and qualify it in a pinned real Tomcat runtime."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time


def sha(path, kind="sha256"):
    digest = hashlib.new(kind)
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tomcat-archive", required=True, type=Path)
    parser.add_argument("--core-jar", required=True, type=Path)
    parser.add_argument("--adapter-jar", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    pins = json.loads((fixture / "runtime.json").read_text())
    if sha(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        raise SystemExit("Tomcat archive does not match the reviewed pin")
    receipt = {"runtime": pins["version"], "archiveSha512": pins["archiveSha512"],
               "coreJarSha256": sha(args.core_jar), "adapterJarSha256": sha(args.adapter_jar),
               "checks": [], "success": False, "ownedProcessStopped": False}
    repo = fixture.parent.parent
    inputs = sorted((repo / "src/main/java").rglob("*.java")) + [repo / "pom.xml", fixture / "ScimServlet.java", Path(__file__), fixture / "runtime.json"]
    receipt["sourceInputs"] = {str(path.relative_to(repo)): sha(path) for path in inputs}
    checks = receipt["checks"]
    args.output.mkdir(parents=True, exist_ok=True)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-scim-tomcat-") as temporary:
            root = Path(temporary)
            with tarfile.open(args.tomcat_archive) as archive:
                # Reviewed official archive is additionally confined to this private root.
                for member in archive.getmembers():
                    destination = (root / member.name).resolve()
                    if not destination.is_relative_to(root.resolve()) or member.issym() or member.islnk():
                        raise RuntimeError("unsafe runtime archive entry")
                archive.extractall(root, filter="data")
            home = root / ("apache-tomcat-" + pins["version"])
            base = root / "instance"
            for name in ("conf", "logs", "temp", "work", "webapps/ROOT/WEB-INF/classes", "webapps/ROOT/WEB-INF/lib"):
                (base / name).mkdir(parents=True)
            shutil.copyfile(home / "conf/web.xml", base / "conf/web.xml")
            classes = base / "webapps/ROOT/WEB-INF/classes"
            jars = base / "webapps/ROOT/WEB-INF/lib"
            shutil.copyfile(args.core_jar, jars / "core.jar")
            shutil.copyfile(args.adapter_jar, jars / "adapter.jar")
            if sha(jars / "core.jar") != receipt["coreJarSha256"] or sha(jars / "adapter.jar") != receipt["adapterJarSha256"]:
                raise RuntimeError("input artifact changed before private copy")
            compilation = subprocess.run([str(args.java_home / "bin/javac"), "--release", "17", "-d", str(classes),
                "-cp", os.pathsep.join(map(str, [args.core_jar, args.adapter_jar, home / "lib/servlet-api.jar"])),
                str(fixture / "ScimServlet.java")], capture_output=True, text=True)
            if compilation.returncode:
                raise RuntimeError("cookbook compilation failed: " + compilation.stderr[:4000])
            checks.append("paired-cookbook-compiled-release17")
            (base / "webapps/ROOT/WEB-INF/web.xml").write_text('<web-app><servlet><servlet-name>scim</servlet-name><servlet-class>example.ScimServlet</servlet-class></servlet><servlet-mapping><servlet-name>scim</servlet-name><url-pattern>/scim/*</url-pattern></servlet-mapping></web-app>')
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
            (base / "conf/server.xml").write_text(f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}" protocol="HTTP/1.1" connectionTimeout="2000" maxHttpRequestHeaderSize="16384" maxHeaderCount="128" maxParameterCount="64" maxPostSize="16384" maxSwallowSize="16384" maxConnections="16" maxThreads="4"/><Engine name="fixture" defaultHost="localhost"><Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/></Engine></Service></Server>')
            credential = secrets.token_urlsafe(32)
            environment = dict(os.environ)
            environment.pop("JAVA_TOOL_OPTIONS", None); environment.pop("JDK_JAVA_OPTIONS", None)
            with (root / "runtime.log").open("wb") as log:
                process = subprocess.Popen([str(args.java_home / "bin/java"), "-Djava.awt.headless=true",
                    "-Dcatalina.home=" + str(home), "-Dcatalina.base=" + str(base), "-Dfixture.credential=" + credential,
                    "-cp", os.pathsep.join(map(str, [home / "bin/bootstrap.jar", home / "bin/tomcat-juli.jar"])),
                    "org.apache.catalina.startup.Bootstrap", "start"], stdout=log, stderr=log, env=environment)

                def request(method, path, body=b"", headers=None, authenticated=True):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                    try:
                        connection.putrequest(method, "/scim" + path)
                        if authenticated: connection.putheader("Authorization", "Bearer " + credential)
                        for name, value in headers or []: connection.putheader(name, value)
                        if body: connection.putheader("Content-Length", str(len(body)))
                        connection.endheaders(body)
                        response = connection.getresponse()
                        payload = response.read(65537)
                        assert len(payload) <= 65536, "bounded-response"
                        return response.status, dict((name.lower(), value) for name, value in response.getheaders()), payload
                    finally:
                        connection.close()

                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None: raise RuntimeError("Tomcat exited before ready")
                    try:
                        status, _, _ = request("GET", "/ServiceProviderConfig")
                        if status == 200: break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline: raise RuntimeError("bounded Tomcat readiness timeout")
                    time.sleep(0.1)
                checks.append("real-container-ready-loopback-only")
                media = [("Content-Type", "application/scim+json")]
                def payload(value): return json.dumps(value, ensure_ascii=False).encode("utf-8")
                def patch(operations): return payload({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": operations})
                for endpoint, required in (("Users", "userName"), ("Groups", "displayName")):
                    schema = "urn:ietf:params:scim:schemas:core:2.0:" + ("User" if endpoint == "Users" else "Group")
                    create = {"schemas": [schema], required: "private+a%20é"}
                    status, headers, body = request("POST", "/" + endpoint, payload(create), media)
                    assert status == 201, "create-201-" + endpoint
                    document = json.loads(body); identity = document["id"]; version = headers["etag"]
                    path = "/" + endpoint + "/" + identity
                    assert document[required] == create[required], "exact-utf8-" + endpoint
                    assert headers["location"] == document["meta"]["location"], "location-meta-" + endpoint
                    assert request("GET", path)[0] == 200, "get-200-" + endpoint
                    conditional = request("GET", path, headers=[("If-None-Match", version)])
                    assert conditional[0] == 304 and conditional[2] == b"" and conditional[1]["etag"] == version, "get-304-" + endpoint
                    replacement = dict(create); replacement[required] = "replaced"
                    stale = request("PUT", path, payload(replacement), media + [("If-Match", '"stale"')])
                    assert stale[0] == 412, "stale-write-412-" + endpoint
                    assert request("GET", path)[1]["etag"] == version, "stale-write-unchanged-" + endpoint
                    status, headers, body = request("PUT", path, payload(replacement), media + [("If-Match", version)])
                    assert status == 200 and json.loads(body)[required] == "replaced", "replace-200-" + endpoint
                    version = headers["etag"]
                    failed = patch([{"op": "replace", "path": required, "value": "partial"}, {"op": "remove", "path": required}])
                    assert request("PATCH", path, failed, media)[0] == 400, "late-patch-rejection-" + endpoint
                    status, headers, body = request("GET", path)
                    assert json.loads(body)[required] == "replaced" and headers["etag"] == version, "late-patch-atomic-" + endpoint
                    no_op = request("PATCH", path, patch([{"op": "replace", "path": required, "value": "replaced"}]), media)
                    assert no_op[0] == (200 if endpoint == "Users" else 204) and no_op[1]["etag"] == version, "noop-version-" + endpoint
                    changed = request("PATCH", path, patch([{"op": "replace", "path": required, "value": "patched"}]), media)
                    assert changed[0] == (200 if endpoint == "Users" else 204), "patch-status-" + endpoint
                    projected = request("PATCH", path + "?attributes=" + required,
                        patch([{"op": "replace", "path": required, "value": "projected"}]), media)
                    assert projected[0] == 200 and json.loads(projected[2])[required] == "projected", "projected-patch-200-" + endpoint
                    assert request("GET", "/" + endpoint + "?count=0")[0] == 200, "count-only-list-" + endpoint
                    assert request("DELETE", path)[0] == 204 and request("GET", path)[0] == 404, "delete-204-404-" + endpoint
                    checks.append("actual-" + endpoint.lower() + "-create-get-put-patch-delete-projection-preconditions-atomic-noop")
                group = payload({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "membership"})
                status, _, body = request("POST", "/Groups", group, media); assert status == 201, "group-membership-create"
                path = "/Groups/" + json.loads(body)["id"]
                add = patch([{"op": "add", "path": "members", "value": [{"value": "u1"}, {"value": "u2"}]}])
                assert request("PATCH", path, add, media)[0] == 204, "group-membership-add"
                remove = patch([{"op": "remove", "path": 'members[value eq "u1"]'}])
                assert request("PATCH", path, remove, media)[0] == 204, "group-membership-remove"
                members = json.loads(request("GET", path)[2])["members"]
                assert [member["value"] for member in members] == ["u2"], "group-membership-ordered-result"
                checks.append("actual-group-membership-add-filtered-remove")
                assert request("GET", "/Users", authenticated=False)[0] == 401, "unauthenticated"
                assert request("GET", "/Users?count=1&count=2")[0] == 400, "raw-query-multiplicity"
                assert request("POST", "/Users", b"{}", media + media)[0] == 415, "physical-content-type-duplicates"
                assert request("POST", "/Users", bytes([0xc3, 0x28]), media)[0] == 400, "malformed-utf8"
                assert request("POST", "/Users", b"a" * 16385, media)[0] == 413, "body-cap-plus-one"
                checks.append("actual-auth-raw-query-physical-headers-malformed-utf8-body-overflow")
                receipt["success"] = True
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                receipt["ownedProcessStopped"] = process.poll() is not None
                process = None
    except Exception as failure:
        receipt["failure"] = str(failure)[:4000]
    finally:
        if process is not None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            receipt["ownedProcessStopped"] = process.poll() is not None
        if receipt["sourceInputs"] != {str(path.relative_to(repo)): sha(path) for path in inputs}:
            receipt["success"] = False; receipt["failure"] = "source changed during qualification"
        (args.output / "RESULT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"success": receipt["success"], "checks": len(checks), "ownedProcessStopped": receipt["ownedProcessStopped"]}))
    if not receipt["success"] or not receipt["ownedProcessStopped"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
