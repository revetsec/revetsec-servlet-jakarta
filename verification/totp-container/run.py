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

"""Qualify application-owned TOTP HTTP behavior through pinned Tomcat 11 on loopback."""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import time


STEP_START = 1792152000  # 2026-10-16T12:00:00Z, the fixture's synthetic clock.
MEDIA = [("Content-Type", "text/plain; charset=UTF-8")]


def digest(path, kind="sha256"):
    value = hashlib.new(kind)
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def otp(manual, when):
    secret = base64.b32decode(manual)
    mac = hmac.new(secret, struct.pack(">Q", when // 30), hashlib.sha1).digest()
    offset = mac[-1] & 15
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7fffffff
    return f"{number % 1000000:06d}".encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__: parser.error("Python optimization disables qualification assertions")
    parser.add_argument("--tomcat-archive", type=Path, required=True)
    parser.add_argument("--core-jar", type=Path, required=True)
    parser.add_argument("--adapter-jar", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    pins = json.loads((repo / "verification/m12-container/runtime.json").read_text())
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive does not match the reviewed runtime pin")
    annotations = [Path.home() / ".m2/repository/org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   Path.home() / ".m2/repository/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar"]
    for item in [args.core_jar, args.adapter_jar, *annotations]:
        if not item.is_file(): parser.error("required JAR is missing: " + str(item))
    auditor = repo / "verification/nullability/NullabilityAudit.java"
    inputs = [fixture / "TotpServlet.java", fixture / "run.py", repo / "docs/ServletTotpRecipe.java", auditor,
              repo / "verification/m12-container/runtime.json"]
    receipt = {"runtime": pins["version"], "archiveSha512": pins["archiveSha512"],
               "coreJarSha256": digest(args.core_jar), "adapterJarSha256": digest(args.adapter_jar),
               "sourceInputs": {str(item.relative_to(repo)): digest(item) for item in inputs},
               "checks": [], "success": False, "ownedProcessStopped": False}
    checks = receipt["checks"]
    args.output.mkdir(parents=True, exist_ok=True)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-totp-jakarta-") as directory:
            root = Path(directory)
            with tarfile.open(args.tomcat_archive) as archive:
                for member in archive.getmembers():
                    destination = (root / member.name).resolve()
                    if not destination.is_relative_to(root.resolve()) or member.issym() or member.islnk():
                        raise RuntimeError("unsafe runtime archive entry")
                archive.extractall(root, filter="data")
            home = root / ("apache-tomcat-" + pins["version"])
            base = root / "instance"
            for name in ("conf", "logs", "temp", "work", "webapps/ROOT/WEB-INF/classes",
                         "webapps/ROOT/WEB-INF/lib"):
                (base / name).mkdir(parents=True)
            shutil.copyfile(home / "conf/web.xml", base / "conf/web.xml")
            classes = base / "webapps/ROOT/WEB-INF/classes"
            libs = base / "webapps/ROOT/WEB-INF/lib"
            shutil.copyfile(args.core_jar, libs / "core.jar")
            shutil.copyfile(args.adapter_jar, libs / "adapter.jar")
            if digest(libs / "core.jar") != receipt["coreJarSha256"] or digest(libs / "adapter.jar") != receipt["adapterJarSha256"]:
                raise RuntimeError("artifact changed during private copy")
            command = [str(args.java_home / "bin/javac"), "--release", "17", "-proc:none",
                       "-Xlint:all", "-Werror", "-d", str(classes), "-cp",
                       os.pathsep.join(map(str, [args.core_jar, args.adapter_jar,
                                                 home / "lib/servlet-api.jar", *annotations])),
                       str(repo / "docs/ServletTotpRecipe.java"), str(fixture / "TotpServlet.java")]
            built = subprocess.run(command, capture_output=True, text=True)
            if built.returncode: raise RuntimeError("TOTP fixture compilation failed: " + built.stderr[:4000])
            checks.append("paired-cookbook-and-fixture-warning-fatal-java17-compile")
            audit_classes = root / "audit-classes"
            audit_classes.mkdir()
            audit_build = subprocess.run([str(args.java_home / "bin/javac"), "--release", "17",
                "-proc:none", "-Xlint:all", "-Werror", "-cp", os.pathsep.join(map(str, annotations)),
                "-d", str(audit_classes), str(auditor)], capture_output=True, text=True)
            if audit_build.returncode:
                raise RuntimeError("Nullability checker compilation failed: " + audit_build.stderr[:4000])
            (root / "audit-sources.txt").write_text(str(repo / "docs/ServletTotpRecipe.java") + "\n"
                                                      + str(fixture / "TotpServlet.java") + "\n")
            (root / "audit-classpath.txt").write_text(os.pathsep.join(map(str, [classes, args.core_jar,
                args.adapter_jar, home / "lib/servlet-api.jar", *annotations])) + "\n")
            audit_run = subprocess.run([str(args.java_home / "bin/java"), "-cp",
                os.pathsep.join(map(str, [audit_classes, *annotations])), "NullabilityAudit",
                str(root / "audit-sources.txt"), str(root / "audit-classpath.txt"),
                str(root / "nullability-audit.json")], capture_output=True, text=True)
            if audit_run.returncode:
                raise RuntimeError("TOTP nullability audit failed: " + audit_run.stderr[:4000])
            audit = json.loads((root / "nullability-audit.json").read_text())
            if audit["missing"] or audit["attribution_errors"]:
                raise RuntimeError("TOTP cookbook/fixture nullability audit has gaps")
            receipt["nullabilityAudit"] = {"checkedReferencePositions": audit["checked_reference_positions"],
                                           "missing": len(audit["missing"]),
                                           "attributionErrors": len(audit["attribution_errors"])}
            checks.append("paired-cookbook-and-fixture-explicit-nullability")
            (base / "webapps/ROOT/WEB-INF/web.xml").write_text(
                '<web-app><servlet><servlet-name>totp</servlet-name><servlet-class>example.TotpServlet</servlet-class>'
                '</servlet><servlet-mapping><servlet-name>totp</servlet-name><url-pattern>/totp/*</url-pattern>'
                '</servlet-mapping></web-app>')
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            (base / "conf/server.xml").write_text(
                f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}"'
                ' protocol="HTTP/1.1" connectionTimeout="2000" maxHttpRequestHeaderSize="16384"'
                ' maxHeaderCount="128" maxParameterCount="64" maxPostSize="70000" maxSwallowSize="70000"'
                ' maxConnections="16" maxThreads="4"/><Engine name="fixture" defaultHost="localhost">'
                '<Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true"'
                ' unpackWARs="false"/></Engine></Service></Server>')
            credential = secrets.token_urlsafe(32)
            environment = dict(os.environ)
            environment.pop("JAVA_TOOL_OPTIONS", None)
            environment.pop("JDK_JAVA_OPTIONS", None)
            with (root / "runtime.log").open("wb") as log:
                process = subprocess.Popen([str(args.java_home / "bin/java"), "-Djava.awt.headless=true",
                    "-Dcatalina.home=" + str(home), "-Dcatalina.base=" + str(base),
                    "-Dfixture.credential=" + credential,
                    "-cp", os.pathsep.join(map(str, [home / "bin/bootstrap.jar", home / "bin/tomcat-juli.jar"])),
                    "org.apache.catalina.startup.Bootstrap", "start"], stdout=log, stderr=log, env=environment)

                def request(method, path, body=b"", headers=(), authenticated=True):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        connection.putrequest(method, "/totp" + path)
                        if authenticated: connection.putheader("X-Fixture-Credential", credential)
                        for name, value in headers: connection.putheader(name, value)
                        if body: connection.putheader("Content-Length", str(len(body)))
                        connection.endheaders(body)
                        response = connection.getresponse()
                        payload = response.read(65537)
                        assert len(payload) <= 65536, "bounded response"
                        return response.status, dict((name.lower(), value) for name, value in response.getheaders()), payload
                    finally:
                        connection.close()

                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None: raise RuntimeError("Tomcat exited before ready")
                    try:
                        if request("GET", "/health")[0] == 200: break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline: raise RuntimeError("bounded Tomcat readiness timeout")
                    time.sleep(0.1)
                assert request("GET", "/health", authenticated=False)[0] == 401
                checks.append("pinned-tomcat-loopback-private-fixture-credential")

                def primary():
                    started = request("GET", "/session/start")
                    assert started[0] == 200 and json.loads(started[2])["primaryPending"] is True
                    assert all(flag in started[1]["set-cookie"] for flag in ("Secure", "HttpOnly", "SameSite=Strict"))
                    cookie = started[1]["set-cookie"].split(";", 1)[0]
                    csrf = started[1]["x-fixture-csrf"]
                    return [("Cookie", cookie), ("Origin", "https://login.example.com"), ("X-Fixture-Csrf", csrf)]

                def code_post(path, code, browser, media=MEDIA):
                    return request("POST", path, code, [*browser, *media])

                browser = primary()
                wrong_origin = [(key, "https://evil.example" if key == "Origin" else value) for key, value in browser]
                wrong_csrf = [(key, "wrong" if key == "X-Fixture-Csrf" else value) for key, value in browser]
                assert request("POST", "/enroll", headers=wrong_origin)[0] == 403
                assert request("POST", "/enroll", headers=wrong_csrf)[0] == 403
                assert request("POST", "/enroll", headers=[*browser, ("Origin", "https://login.example.com")])[0] == 403
                assert request("POST", "/enroll", headers=[*browser, ("Cookie", browser[0][1])])[0] == 403
                assert request("POST", "/enroll", headers=[*browser, ("X-Fixture-Csrf", browser[2][1])])[0] == 403
                enrollment = request("POST", "/enroll", headers=browser)
                assert enrollment[0] == 200
                setup = json.loads(enrollment[2])
                manual = setup["manualEntryKey"]
                assert setup["provisioningUri"].startswith("otpauth://totp/")
                checks.append("enrollment-admission-origin-csrf-cookie-duplicates-and-secret-response")

                code = otp(manual, STEP_START)
                assert code_post("/confirm", code, browser, media=[])[0] == 415
                assert code_post("/confirm", code, browser, media=MEDIA + MEDIA)[0] == 415
                assert code_post("/confirm", code, browser, media=[("Content-Type", "application/x-www-form-urlencoded")])[0] == 415
                confirmed = code_post("/confirm", code, browser)
                assert confirmed[0] == 200, "confirmation"
                issued = json.loads(confirmed[2])["codes"]
                assert len(issued) == 10
                assert code_post("/confirm", code, browser)[0] == 403, "confirmation replay"
                checks.append("raw-code-media-and-confirmation-replay")

                status = request("GET", "/status", headers=browser)
                head = request("HEAD", "/status", headers=browser)
                assert status[0] == head[0] == 200 and head[2] == b""
                assert status[1]["content-length"] == head[1]["content-length"]
                assert json.loads(status[2])["active"] is True
                assert manual.encode() not in status[2]
                checks.append("status-get-head-same-metadata-no-head-body-or-secret")

                assert request("POST", "/test/advance")[0] == 204
                login_code = otp(manual, STEP_START + 30)
                login_browser = primary()
                assert code_post("/login", login_code, wrong_origin)[0] == 403
                assert code_post("/login", login_code, wrong_csrf)[0] == 403
                assert code_post("/login", login_code, login_browser, media=[])[0] == 415
                assert code_post("/login", login_code, login_browser, media=MEDIA + MEDIA)[0] == 415
                assert code_post("/login", b"1" * 129, login_browser)[0] == 413
                assert code_post("/login", b"\xff", login_browser)[0] == 400
                signed_in = code_post("/login", login_code, login_browser)
                assert signed_in[0] == 200 and json.loads(signed_in[2])["authenticated"] is True
                strong = [("Cookie", signed_in[1]["set-cookie"].split(";", 1)[0]),
                          ("Origin", "https://login.example.com"),
                          ("X-Fixture-Csrf", signed_in[1]["x-fixture-csrf"])]
                assert strong[0][1] != login_browser[0][1] and strong[2][1] != login_browser[2][1]
                assert request("GET", "/status", headers=login_browser)[0] == 403
                replay_browser = primary()
                assert code_post("/login", login_code, replay_browser)[0] == 403
                checks.append("totp-login-rotates-cookie-and-csrf-old-session-and-step-replay-denied")

                assert request("POST", "/test/close")[0] == 204
                closed = request("GET", "/status", headers=strong)
                assert closed[0] == 503 and "set-cookie" not in closed[1]
                assert request("GET", "/session/start")[0] == 503
                assert request("POST", "/test/open")[0] == 204
                assert request("GET", "/status", headers=strong)[0] == 200
                checks.append("closed-fixture-gate-withholds-status-and-cookie")

                assert request("POST", "/test/expire-on-close")[0] == 204
                expired = request("POST", "/replace", headers=strong)
                assert expired[0] == 503 and b"manualEntryKey" not in expired[2] and "set-cookie" not in expired[1]
                assert request("POST", "/cancel", headers=strong)[0] == 200
                checks.append("outer-permit-close-deadline-withholds-setup-secret")

                assert request("POST", "/test/expire-on-close")[0] == 204
                expiring_browser = primary()
                expired_login = code_post("/recovery", issued[2].encode("ascii"), expiring_browser)
                assert expired_login[0] == 503 and "set-cookie" not in expired_login[1]
                assert request("GET", "/status", headers=expiring_browser)[0] == 403
                assert code_post("/recovery", issued[2].encode("ascii"), primary())[0] == 403
                checks.append("outer-permit-close-deadline-withholds-recovery-cookie-after-consumption")

                recovery_browser = primary()
                recovered = code_post("/recovery", issued[0].encode("ascii"), recovery_browser)
                assert recovered[0] == 200 and json.loads(recovered[2])["recoverySession"] is True
                restricted = [("Cookie", recovered[1]["set-cookie"].split(";", 1)[0]),
                              ("Origin", "https://login.example.com"),
                              ("X-Fixture-Csrf", recovered[1]["x-fixture-csrf"])]
                assert request("GET", "/status", headers=recovery_browser)[0] == 403
                assert request("POST", "/rotate", headers=restricted)[0] == 403
                assert request("POST", "/remove", headers=restricted)[0] == 403
                assert request("POST", "/replace", headers=restricted)[0] == 403
                replay_recovery = primary()
                assert code_post("/recovery", issued[0].encode("ascii"), replay_recovery)[0] == 403
                checks.append("recovery-code-login-restricted-session-and-code-replay-denied")

                rotated = request("POST", "/rotate", headers=strong)
                assert rotated[0] == 200
                replacement_codes = json.loads(rotated[2])["codes"]
                assert len(replacement_codes) == 10 and replacement_codes != issued
                assert code_post("/recovery", issued[1].encode("ascii"), primary())[0] == 403
                checks.append("authorized-recovery-rotation-invalidates-old-batch")

                assert request("POST", "/test/unknown")[0] == 204
                uncertain_browser = primary()
                uncertain = code_post("/recovery", replacement_codes[0].encode("ascii"), uncertain_browser)
                assert uncertain[0] == 503 and "set-cookie" not in uncertain[1]
                assert code_post("/recovery", replacement_codes[0].encode("ascii"), primary())[0] == 403
                remaining = json.loads(request("GET", "/status", headers=strong)[2])["remainingRecoveryCodes"]
                assert remaining == 9, "unknown acknowledgement followed committed code consumption"
                checks.append("lost-final-commit-ack-withholds-cookie-and-consumed-code-replays-denied")

                removed = request("POST", "/remove", headers=strong)
                assert removed[0] == 200 and json.loads(removed[2])["removed"] is True
                assert request("GET", "/status", headers=strong)[0] == 403
                checks.append("factor-removal-invalidates-fixture-sessions")
                receipt["success"] = True
    except Exception as failure:
        receipt["failure"] = type(failure).__name__ + ": " + str(failure)
        raise
    finally:
        if process is not None:
            process.terminate()
            try: process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=8)
            receipt["ownedProcessStopped"] = process.poll() is not None
        receipt["sourceInputsUnchanged"] = all(
            digest(repo / relative) == expected for relative, expected in receipt["sourceInputs"].items())
        if not receipt["sourceInputsUnchanged"]:
            receipt["success"] = False
            receipt["failure"] = "Source changed during qualification"
        if process is not None and not receipt["ownedProcessStopped"]:
            receipt["success"] = False
            receipt["failure"] = "Owned Tomcat process did not stop"
        (args.output / "RESULT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["success"]: raise RuntimeError(receipt.get("failure", "TOTP qualification failed"))
    print("Jakarta TOTP Tomcat checks passed: " + str(args.output / "RESULT.json"))


if __name__ == "__main__":
    main()
