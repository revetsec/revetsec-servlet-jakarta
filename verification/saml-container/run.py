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

"""Qualify HTTP-POST SAML logout transport in a private pinned real Tomcat runtime."""
import argparse
import base64
import hashlib
import http.client
import html
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET


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
    inputs = sorted((repo / "src/main/java").rglob("*.java")) + [repo / "pom.xml", fixture / "SamlServlet.java", fixture / "SamlFixture.java", Path(__file__), fixture / "runtime.json"]
    receipt["sourceInputs"] = {str(path.relative_to(repo)): sha(path) for path in inputs}
    checks = receipt["checks"]
    args.output.mkdir(parents=True, exist_ok=True)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-saml-tomcat-") as temporary:
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
                str(fixture / "SamlServlet.java"), str(fixture / "SamlFixture.java")], capture_output=True, text=True)
            if compilation.returncode:
                raise RuntimeError("cookbook compilation failed: " + compilation.stderr[:4000])
            checks.append("paired-saml-fixture-compiled-release17")
            (base / "webapps/ROOT/WEB-INF/web.xml").write_text('<web-app><servlet><servlet-name>saml</servlet-name><servlet-class>example.SamlServlet</servlet-class></servlet><servlet-mapping><servlet-name>saml</servlet-name><url-pattern>/saml/*</url-pattern></servlet-mapping></web-app>')
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
            (base / "conf/server.xml").write_text(f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}" protocol="HTTP/1.1" connectionTimeout="2000" maxHttpRequestHeaderSize="16384" maxHeaderCount="128" maxParameterCount="64" maxPostSize="2100000" maxSwallowSize="2100000" maxConnections="16" maxThreads="4"/><Engine name="fixture" defaultHost="localhost"><Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/></Engine></Service></Server>')
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
                        connection.putrequest(method, "/saml" + path)
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
                        status, _, _ = request("GET", "/begin")
                        if status == 200: break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline: raise RuntimeError("bounded Tomcat readiness timeout")
                    time.sleep(0.1)
                checks.append("real-container-ready-loopback-only")
                media = [("Content-Type", "application/x-www-form-urlencoded")]
                status, headers, form = request("GET", "/begin")
                assert status == 200 and headers["content-type"].replace(" ", "").lower() == "text/html;charset=utf-8", "prepared-request-html"
                assert headers["cache-control"] == "no-store" and headers["referrer-policy"] == "no-referrer", "request-response-policy"
                assert int(headers["content-length"]) == len(form), "exact-request-content-length"
                assert "Secure" in headers["set-cookie"] and "SameSite=None" in headers["set-cookie"], "application-owned-post-cookie"
                assert form == request("GET", "/fixture/form")[2], "exact-core-prepared-html"
                assert b'name="SAMLRequest"' in form and b'name="SAMLResponse"' not in form, "request-field-kind"
                checks.append("actual-post-logout-request-exact-form-headers-length-cookie")

                idp_request = request("GET", "/fixture/request")[2]
                idp_response = request("GET", "/fixture/response")[2]
                def tamper(body, field, before, after):
                    fields = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True)
                    xml = base64.b64decode(fields[field][0], validate=True)
                    changed = xml.replace(before, after)
                    assert changed != xml, "fixture-mutation-applied"
                    fields[field] = [base64.b64encode(changed).decode("ascii")]
                    return urllib.parse.urlencode([(key, value[0]) for key, value in fields.items()]).encode("ascii")

                assert request("POST", "/logout", tamper(idp_response, "SAMLResponse",
                    b'_logout-response', b'_mutated-response'), media)[0] == 400, "response-signature-rejection"
                assert request("POST", "/logout", idp_response, media)[0] == 204, "response-success-after-invalid-signature"
                assert request("POST", "/logout", idp_response, media)[0] == 400, "response-replay-rejection"
                checks.append("actual-signed-post-response-signature-pending-preservation-success-replay")

                assert request("POST", "/logout", tamper(idp_request, "SAMLRequest", b'alice', b'bobby'), media)[0] == 400, "request-signature-rejection"
                status, headers, answer = request("POST", "/logout", idp_request, media)
                assert status == 200 and headers["cache-control"] == "no-store", "idp-request-accepted"
                assert int(headers["content-length"]) == len(answer), "exact-response-content-length"
                assert b'name="SAMLResponse"' in answer and b'name="SAMLRequest"' not in answer, "response-field-kind"
                fields = {key.decode("ascii"): html.unescape(value.decode("utf-8"))
                          for key, value in re.findall(rb'<input type="hidden" name="([^"]+)" value="([^"]*)">', answer)}
                assert fields["RelayState"] == "opaque+relay", "opaque-relay-state"
                xml = ET.fromstring(base64.b64decode(fields["SAMLResponse"], validate=True))
                assert xml.attrib["InResponseTo"] == "_idp-logout" and xml.attrib["Destination"] == "https://idp.example.test/logout", "response-correlation-destination"
                assert xml.find("{http://www.w3.org/2000/09/xmldsig#}Signature") is not None, "response-root-signature"
                assert request("POST", "/logout", idp_request, media)[0] == 400, "request-replay-rejection"
                checks.append("actual-signed-post-idp-request-signature-validation-response-form-replay")

                assert request("POST", "/acs", idp_request, media)[0] == 400, "acs-response-only"
                assert request("POST", "/acs", idp_response, media)[0] == 400, "logout-response-rejected-as-login"
                assert request("POST", "/logout?SAMLRequest=evil", idp_request, media)[0] == 400, "raw-query-pollution"
                assert request("POST", "/logout?RelayState=evil", idp_request, media)[0] == 400, "relay-query-pollution"
                assert request("POST", "/logout", idp_request, media + media)[0] == 400, "physical-content-type-duplicates"
                assert request("POST", "/logout", idp_request + b"&SAMLResponse=PGEvPg%3D%3D", media)[0] == 400, "mixed-message-fields"
                assert request("POST", "/logout", idp_request + b"&SAMLRequest=PGEvPg%3D%3D", media)[0] == 400, "duplicate-message-field"
                assert request("POST", "/logout", b"SAMLRequest=%C3%28", media)[0] == 400, "malformed-utf8"
                assert request("POST", "/logout", b"a" * 1061129, media)[0] == 400, "adapter-body-cap-plus-one"
                assert request("GET", "/logout")[0] == 405, "method-mismatch"
                assert request("POST", "/logout", idp_request, media, authenticated=False)[0] == 401, "fixture-authentication"
                checks.append("actual-acs-separation-query-header-body-multiplicity-utf8-overflow-method-auth")
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
