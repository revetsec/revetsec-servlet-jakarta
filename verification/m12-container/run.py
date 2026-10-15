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

"""Qualify OAuth, bearer, issuer and WebAuthn through the Jakarta adapter in real Tomcat."""
import argparse
import base64
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
import urllib.parse


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
    inputs = (sorted((repo / "src/main/java").rglob("*.java"))
              + sorted(fixture.glob("*.java"))
              + [repo / "pom.xml", Path(__file__), fixture / "runtime.json"])
    receipt["sourceInputs"] = {str(path.relative_to(repo)): sha(path) for path in inputs}
    checks = receipt["checks"]
    args.output.mkdir(parents=True, exist_ok=True)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-m12-tomcat-") as temporary:
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
                *map(str, sorted(fixture.glob("*.java")))], capture_output=True, text=True)
            if compilation.returncode:
                raise RuntimeError("M12 fixture compilation failed: " + compilation.stderr[:4000])
            checks.append("paired-m12-fixture-compiled-release17")
            (base / "webapps/ROOT/WEB-INF/web.xml").write_text('<web-app><servlet><servlet-name>m12</servlet-name><servlet-class>example.M12Servlet</servlet-class></servlet><servlet-mapping><servlet-name>m12</servlet-name><url-pattern>/m12/*</url-pattern></servlet-mapping></web-app>')
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
            (base / "conf/server.xml").write_text(f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}" protocol="HTTP/1.1" connectionTimeout="2000" maxHttpRequestHeaderSize="16384" maxHeaderCount="128" maxParameterCount="64" maxPostSize="70000" maxSwallowSize="70000" maxConnections="16" maxThreads="4"/><Engine name="fixture" defaultHost="localhost"><Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/></Engine></Service></Server>')
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
                        connection.putrequest(method, "/m12" + path)
                        if authenticated: connection.putheader("X-Fixture-Credential", credential)
                        for name, value in headers or []: connection.putheader(name, value)
                        if body: connection.putheader("Content-Length", str(len(body)))
                        connection.endheaders(body)
                        response = connection.getresponse()
                        payload = response.read(65537)
                        assert len(payload) <= 65536, "bounded-response"
                        fields = response.getheaders()
                        return response.status, dict((name.lower(), value) for name, value in fields), payload, fields
                    finally:
                        connection.close()

                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None: raise RuntimeError("Tomcat exited before ready")
                    try:
                        status, _, _, _ = request("GET", "/health")
                        if status == 200: break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline: raise RuntimeError("bounded Tomcat readiness timeout")
                    time.sleep(0.1)
                checks.append("real-container-ready-loopback-only-private-credential")
                assert request("GET", "/health", authenticated=False)[0] == 401, "private-fixture-gate"
                session = request("GET", "/session/start")
                assert session[0] == 200, "app-browser-session-issued"
                assert all(flag in session[1]["set-cookie"] for flag in ("Secure", "HttpOnly", "SameSite=Strict")), "app-cookie-policy"
                cookie = session[1]["set-cookie"].split(";", 1)[0]
                csrf = session[1]["x-fixture-csrf"]
                browser = [("Cookie", cookie), ("Origin", "https://login.example.com"), ("X-Fixture-Csrf", csrf)]
                wrong_origin = [("Cookie", cookie), ("Origin", "https://attacker.example"), ("X-Fixture-Csrf", csrf)]
                wrong_csrf = [("Cookie", cookie), ("Origin", "https://login.example.com"), ("X-Fixture-Csrf", "wrong")]
                other_session = request("GET", "/session/start")
                assert other_session[0] == 200, "second-browser-session-issued"
                other_cookie = other_session[1]["set-cookie"].split(";", 1)[0]
                other_csrf = other_session[1]["x-fixture-csrf"]
                assert other_cookie != cookie and other_csrf != csrf, "independent-browser-session-secrets"
                other_browser = [("Cookie", other_cookie), ("Origin", "https://login.example.com"),
                    ("X-Fixture-Csrf", other_csrf)]
                checks.append("app-browser-cookie-independent-binding-origin-csrf")
                redirect = request("GET", "/oauth/redirect")
                assert redirect[0] == 302 and redirect[1]["location"] == "https://provider.example/authorize?state=opaque%2Bstate", "oauth-redirect"
                assert redirect[1]["cache-control"] == "no-store" and redirect[1]["referrer-policy"] == "no-referrer", "oauth-redirect-policy"
                assert request("GET", "/oauth/callback?code=abc&state=opaque%2Bvalue")[2] == b"QUERY:opaque+value", "oauth-raw-query"
                form = [("Content-Type", "application/x-www-form-urlencoded")]
                posted = request("POST", "/oauth/callback?tenant=one", b"code=abc&state=post%2Bstate", form)
                assert posted[0] == 200 and posted[2] == b"FORM_POST:post+state", "oauth-form-post"
                assert request("GET", "/oauth/callback?code=a&code=b&state=x")[0] == 400, "oauth-duplicate-code"
                assert request("POST", "/oauth/callback?state=evil", b"code=abc&state=good", form)[0] == 400, "oauth-split-channel"
                assert request("POST", "/oauth/callback", b"code=abc&state=good", form + form)[0] == 400, "oauth-physical-content-type-duplicate"
                assert request("POST", "/oauth/callback", b"code=%C3%28&state=good", form)[0] == 400, "oauth-malformed-utf8"
                checks.append("actual-oauth-redirect-query-form-post-ambiguity-and-utf8")

                assert request("GET", "/bearer")[0] == 401, "bearer-absent"
                assert request("GET", "/bearer?access_token=secret")[0] == 401, "bearer-query-ignored"
                opaque = request("GET", "/bearer", headers=[("Authorization", "Bearer opaque.token")])
                assert opaque[0] == 401 and "invalid_token" in opaque[1]["www-authenticate"], "bearer-unverified-token-denied"
                assert request("GET", "/bearer", headers=[("Authorization", "Basic abc")])[0] == 400, "bearer-other-scheme"
                assert request("GET", "/bearer", headers=[("Authorization", "Bearer a"), ("Authorization", "Bearer a")])[0] == 400, "bearer-physical-duplicates"
                checks.append("actual-bearer-parse-denied-unverified-and-physical-duplicates")

                metadata = request("GET", "/as/metadata")
                assert metadata[0] == 200 and json.loads(metadata[2])["issuer"] == "https://login.example.com/tenant", "issuer-metadata"
                assert metadata[1]["content-length"] == str(len(metadata[2])) and metadata[1]["cache-control"], "issuer-metadata-headers"
                jwks = request("GET", "/as/jwks")
                assert jwks[0] == 200 and len(json.loads(jwks[2])["keys"]) >= 1, "issuer-jwks"
                query = urllib.parse.urlencode({"client_id": "m12-client", "response_type": "code",
                    "redirect_uri": "https://client.example/cb?original=%2f", "resource": "https://resource.example/mcp",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256", "state": "opaque-state"})
                assert request("GET", "/as/authorize?" + query)[0] == 403, "issuer-session-required"
                assert request("GET", "/as/authorize?" + query, headers=wrong_origin)[0] == 403, "issuer-origin-required"
                assert request("GET", "/as/authorize?" + query, headers=wrong_csrf)[0] == 403, "issuer-csrf-required"
                begin = request("GET", "/as/authorize?" + query, headers=browser)
                assert begin[0] == 200 and len(begin[2]) > 20, "issuer-authorization-interaction"
                interaction = begin[2].decode("ascii")
                assert request("POST", "/as/approve?interaction=" + interaction, headers=wrong_csrf)[0] == 403, "issuer-approval-csrf"
                assert request("POST", "/as/approve?interaction=" + interaction, headers=wrong_origin)[0] == 403, "issuer-approval-origin"
                cross_session_approval = request("POST", "/as/approve?interaction=" + interaction, headers=other_browser)
                assert cross_session_approval[0] == 400 and "location" not in cross_session_approval[1], "issuer-cross-session-no-code"
                approved = request("POST", "/as/approve?interaction=" + interaction, headers=browser)
                assert approved[0] == 303 and approved[1]["cache-control"] == "no-store", "issuer-approved-redirect"
                location = urllib.parse.urlsplit(approved[1]["location"])
                assert location.scheme == "https" and location.netloc == "client.example", "issuer-registered-redirect"
                code = urllib.parse.parse_qs(location.query)["code"][0]
                assert code.startswith("rsc1_"), "issuer-code"
                token_form = urllib.parse.urlencode({"grant_type": "authorization_code", "client_id": "m12-client",
                    "resource": "https://resource.example/mcp", "code": code,
                    "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    "redirect_uri": "https://client.example/cb?original=%2f"}).encode("ascii")
                issued = request("POST", "/as/token", token_form, form)
                assert issued[0] == 200 and json.loads(issued[2])["access_token"], "issuer-token-issuance"
                access_token = json.loads(issued[2])["access_token"]
                assert issued[1]["content-length"] == str(len(issued[2])), "issuer-token-exact-length"
                assert request("GET", "/bearer", headers=[("Authorization", "Bearer " + access_token)])[0] == 204, "issued-bearer-validated"
                assert request("POST", "/as/token?code=evil", token_form, form)[0] == 400, "issuer-query-pollution"
                assert request("POST", "/as/token", token_form, form + form)[0] == 400, "issuer-duplicate-content-type"
                assert request("GET", "/as/token")[0] == 405, "issuer-method"
                basic = ("Authorization", "Basic " + base64.b64encode(b"resource:secret").decode("ascii"))
                introspection_body = urllib.parse.urlencode({"token": access_token}).encode("ascii")
                active = request("POST", "/as/introspect", introspection_body, form + [basic])
                assert active[0] == 200 and json.loads(active[2])["active"] is True, "issuer-introspection-active-status-" + str(active[0])
                revocation_body = urllib.parse.urlencode({"client_id": "m12-client", "token": access_token}).encode("ascii")
                revoked = request("POST", "/as/revoke", revocation_body, form)
                assert revoked[0] == 200, "issuer-revocation"
                inactive = request("POST", "/as/introspect", introspection_body, form + [basic])
                assert inactive[0] == 200 and json.loads(inactive[2])["active"] is False, "issuer-introspection-inactive"
                assert request("GET", "/bearer", headers=[("Authorization", "Bearer " + access_token)])[0] == 401, "revoked-bearer-denied"
                assert request("POST", "/as/token", token_form, form)[0] == 400, "issuer-code-replay"
                checks.append("actual-issuer-metadata-jwks-code-token-introspection-revocation-and-ingress-rejections")

                assert request("POST", "/wa/register/start")[0] == 403, "webauthn-start-session-required"
                assert request("POST", "/wa/register/start", headers=wrong_origin)[0] == 403, "webauthn-start-origin-required"
                assert request("POST", "/wa/register/start", headers=wrong_csrf)[0] == 403, "webauthn-start-csrf-required"
                started = request("POST", "/wa/register/start", headers=browser)
                assert started[0] == 200 and started[1]["cache-control"] == "no-store", "webauthn-registration-start"
                assert started[1]["content-length"] == str(len(started[2])), "webauthn-exact-json-length"
                registration = json.loads(started[2]); challenge = registration["publicKey"]["challenge"]
                ceremony = registration["ceremonyId"]
                assert registration["publicKey"]["rp"]["id"] == "login.example.com", "webauthn-rp-id"
                assert registration["publicKey"]["authenticatorSelection"]["residentKey"] == "required", "webauthn-resident-key"
                json_media = [("Content-Type", "application/json")]
                sample = request("GET", "/wa/test/registration-response?challenge=" + challenge)[2]
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, sample, json_media)[0] == 403, "webauthn-completion-session-required"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, sample, json_media + wrong_csrf)[0] == 403, "webauthn-completion-csrf-required"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, sample, json_media + wrong_origin)[0] == 403, "webauthn-completion-origin-required"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, sample, json_media + other_browser)[0] == 400, "webauthn-cross-session-no-registration"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, sample, json_media + browser)[0] == 204, "webauthn-registration-complete"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, sample, json_media + browser)[0] == 400, "webauthn-registration-replay"
                sign_in = json.loads(request("POST", "/wa/authenticate/start", headers=browser)[2])
                assert "allowCredentials" not in sign_in["publicKey"], "webauthn-discoverable-sign-in"
                challenge = sign_in["publicKey"]["challenge"]; ceremony = sign_in["ceremonyId"]
                wrong = request("GET", "/wa/test/assertion-response?challenge=" + ("A" * 43))[2]
                assert request("POST", "/wa/authenticate/complete?ceremony=" + ceremony, wrong, json_media + browser)[0] == 400, "webauthn-wrong-challenge"
                assertion = request("GET", "/wa/test/assertion-response?challenge=" + challenge)[2]
                assert request("POST", "/wa/authenticate/complete?ceremony=" + ceremony, assertion, json_media + browser)[0] == 204, "webauthn-authentication-complete"
                assert request("POST", "/wa/authenticate/complete?ceremony=" + ceremony, assertion, json_media + browser)[0] == 400, "webauthn-authentication-replay"
                step_up = json.loads(request("POST", "/wa/reauthenticate/start", headers=browser)[2])
                step_challenge = step_up["publicKey"]["challenge"]
                step_assertion = request("GET", "/wa/test/assertion-response?challenge=" + step_challenge + "&counter=2")[2]
                assert request("POST", "/wa/reauthenticate/complete?ceremony=" + step_up["ceremonyId"], step_assertion, json_media + browser)[0] == 204, "webauthn-reauthentication-complete"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, b"{}", json_media + json_media + browser)[0] == 400, "webauthn-physical-content-type-duplicate"
                assert request("POST", "/wa/register/complete?ceremony=" + ceremony, b"a" * 4097, json_media + browser)[0] == 400, "webauthn-body-cap-plus-one"
                checks.append("actual-webauthn-registration-sign-in-reauthentication-replay-and-body-boundaries")
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
