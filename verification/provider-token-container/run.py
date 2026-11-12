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

"""Qualify paired R9/R10 application carriers in an owned pinned loopback Tomcat instance."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error("Python optimization disables qualification assertions")
    parser.add_argument("--tomcat-archive", type=Path, required=True)
    parser.add_argument("--core-jar", type=Path, required=True)
    parser.add_argument("--core-sha256", required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--common-source-directory", type=Path)
    parser.add_argument("--recipe-source", type=Path, help="Private carrier calibration override; recorded by exact digest")
    parser.add_argument("--annotations-repository", type=Path, default=Path.home()/".m2/repository")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    common = args.common_source_directory or repo.parent/"revetsec/examples/provider-backend-tokens/src/main/java/example/provider"
    recipe = args.recipe_source or repo/"docs/ServletProviderTokensRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar"]
    sources = [recipe, fixture/"ProviderTokensServlet.java", fixture/"ProviderFixture.java",
               common/"BackendApplication.java", common/"ProviderTokens.java", common/"package-info.java"]
    auditor = repo/"verification/nullability/NullabilityAudit.java"
    for item in [args.tomcat_archive, args.core_jar, *annotations, *sources, auditor, pins_path]:
        if not item.is_file(): parser.error("Required input missing: "+str(item))
    if not re.fullmatch("[0-9a-f]{64}", args.core_sha256) or digest(args.core_jar) != args.core_sha256:
        parser.error("Selected core SHA256 mismatch before instance creation")
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive differs from reviewed SHA512")
    if args.output.exists(): parser.error("Use a fresh evidence output directory")
    inputs = {str(p.resolve()): digest(p) for p in [*sources, auditor, pins_path, Path(__file__)]}
    receipt = {"namespace": namespace, "runtime": pins["version"], "runtimeSha512": pins["archiveSha512"],
               "coreJarSha256": args.core_sha256, "sourceInputs": inputs, "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Synthetic provider/JWKS/account collaborators; real Servlet container; no hosted provider, TLS handshake or S1-S4 formal pentest claim"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-provider-"+namespace+"-") as directory:
            instance = Path(directory)
            try:
                with tarfile.open(args.tomcat_archive) as archive:
                    for member in archive.getmembers():
                        if not (instance/member.name).resolve().is_relative_to(instance.resolve()) or member.issym() or member.islnk():
                            raise RuntimeError("Unsafe runtime archive entry")
                    archive.extractall(instance, filter="data")
                home = instance/("apache-tomcat-"+pins["version"])
                base = instance/"instance"
                for name in ["conf", "logs", "temp", "work", "webapps/ROOT/WEB-INF/classes", "webapps/ROOT/WEB-INF/lib"]:
                    (base/name).mkdir(parents=True)
                shutil.copyfile(home/"conf/web.xml", base/"conf/web.xml")
                classes = base/"webapps/ROOT/WEB-INF/classes"
                copied_core = base/"webapps/ROOT/WEB-INF/lib/core.jar"
                shutil.copyfile(args.core_jar, copied_core)
                if digest(copied_core) != args.core_sha256: raise RuntimeError("Selected artifact changed during copy")
                classpath = os.pathsep.join(map(str, [args.core_jar, home/"lib/servlet-api.jar", *annotations]))
                command = [str(args.java_home/"bin/javac"), "--release", "17", "-proc:none", "-Xlint:all", "-Werror",
                           "-cp", classpath, "-d", str(classes), *map(str, sources)]
                compiled = subprocess.run(command, capture_output=True, text=True)
                (args.output/"compile.log").write_text(compiled.stdout+compiled.stderr)
                if compiled.returncode: raise RuntimeError("Warning-fatal source compilation failed")
                if any(digest(Path(path)) != value for path, value in inputs.items()):
                    raise RuntimeError("Qualification source changed during compile")
                receipt["checks"].append({"name": "warning-fatal-release17-compile", "passed": True})
                audit_classes = instance/"audit"; audit_classes.mkdir()
                audit_compile = subprocess.run([str(args.java_home/"bin/javac"), "--release", "17", "-proc:none", "-Xlint:all", "-Werror", "-cp",
                    os.pathsep.join(map(str, annotations)), "-d", str(audit_classes), str(auditor)], capture_output=True, text=True)
                (args.output/"audit-compile.log").write_text(audit_compile.stdout+audit_compile.stderr)
                if audit_compile.returncode: raise RuntimeError("Nullability checker compilation failed")
                (instance/"sources.txt").write_text("".join(str(p)+"\n" for p in sources))
                (instance/"classpath.txt").write_text(str(classes)+os.pathsep+classpath)
                audited = subprocess.run([str(args.java_home/"bin/java"), "-cp", os.pathsep.join(map(str, [audit_classes, *annotations])),
                    "NullabilityAudit", str(instance/"sources.txt"), str(instance/"classpath.txt"), str(args.output/"nullability.json")], capture_output=True, text=True)
                (args.output/"audit.log").write_text(audited.stdout+audited.stderr)
                if audited.returncode: raise RuntimeError("Explicit source nullability audit failed")
                receipt["checks"].append({"name": "explicit-nullability-attributed", "passed": True})
                (base/"webapps/ROOT/WEB-INF/web.xml").write_text(
                    '<web-app><servlet><servlet-name>providers</servlet-name><servlet-class>example.ProviderTokensServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>providers</servlet-name>'
                    '<url-pattern>/providers/*</url-pattern></servlet-mapping></web-app>')
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
                # Fixed loopback fixture trust only: secure=true is not a real TLS handshake qualification.
                (base/"conf/server.xml").write_text(
                    f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}"'
                    ' protocol="HTTP/1.1" scheme="https" secure="true" connectionTimeout="2000"'
                    ' disableUploadTimeout="false" connectionUploadTimeout="2000" maxHttpRequestHeaderSize="16384"'
                    ' maxHeaderCount="64" maxParameterCount="32" maxPostSize="70000" maxSwallowSize="70000"'
                    ' maxConnections="16" maxThreads="8" acceptCount="8"/><Engine name="fixture" defaultHost="localhost">'
                    '<Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/>'
                    '</Engine></Service></Server>')
                credential = secrets.token_urlsafe(32)
                environment = dict(os.environ)
                environment.pop("JAVA_TOOL_OPTIONS", None); environment.pop("JDK_JAVA_OPTIONS", None)
                environment["REVETSEC_PROVIDER_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_PROVIDER_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_PROVIDER_CORE_SHA256"] = args.core_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, "/providers"+path, skip_host=True, skip_accept_encoding=True)
                            connection.putheader("Host", "app.example")
                            if authenticated: connection.putheader("X-Fixture-Credential", credential)
                            for name, value in headers: connection.putheader(name, value)
                            if chunked: connection.putheader("Transfer-Encoding", "chunked")
                            elif body: connection.putheader("Content-Length", str(len(body)))
                            connection.endheaders()
                            if chunked:
                                connection.send((f"{len(body):x}\r\n").encode()+body+b"\r\n0\r\n\r\n")
                            elif body: connection.send(body)
                            response = connection.getresponse()
                            payload = response.read(65537)
                            assert len(payload) <= 65536, "bounded-response"
                            fields = response.getheaders()
                            with request_lock:
                                receipt["requests"].append({"method":method,"path":path,"status":response.status,
                                    "bodySha256":hashlib.sha256(payload).hexdigest(),
                                    "cookieCount":sum(name.lower()=="set-cookie" for name,value in fields)})
                            return response.status, fields, payload
                        finally: connection.close()

                    def check(name, condition, observed=None):
                        nonlocal current
                        current = name
                        receipt["checks"].append({"name": name, "passed": bool(condition), "observed": observed})
                        assert condition, name

                    def data(reply): return json.loads(reply[2])
                    def cookies(reply): return [v for k, v in reply[1] if k.lower()=="set-cookie"]
                    def cookie(reply, name):
                        found = [v.split(";", 1)[0] for v in cookies(reply) if v.startswith(name+"=")]
                        assert len(found)==1, "one-cookie-"+name
                        return found[0]
                    def state(): return data(request("GET", "/fixture/state"))
                    def control(command): return request("GET", "/fixture/"+command)
                    def encoded(fields): return urllib.parse.urlencode(fields).encode("ascii")
                    media = [("Content-Type", "application/x-www-form-urlencoded")]
                    origin = [("Origin", "https://app.example")]
                    def begin(provider, browser=(), fields=None):
                        return request("POST", "/"+provider+"/begin", encoded(fields or {"begin":"1"}), [*media, *(origin if provider=="google" else []), *browser])
                    def token(provider, started, mode="valid"):
                        reply = request("GET", "/fixture/token/"+provider+"/"+mode, headers=[("X-Fixture-Nonce", data(started)["nonce"])])
                        assert reply[0]==200, "private-signing-fixture"
                        return data(reply)["token"]
                    def completion(provider, started, compact, extra=(), csrf="TEST-ONLY-csrf"):
                        if provider=="google":
                            body = encoded({"credential":compact,"g_csrf_token":csrf})
                            headers = [*media, ("Cookie",cookie(started,"__Host-provider-login")+"; g_csrf_token=TEST-ONLY-csrf"), *extra]
                        else:
                            body = encoded({"request_id":data(started)["request_id"],"request_binding":data(started)["request_binding"],"identity_token":compact})
                            headers = [*media, *extra]
                        return request("POST", "/"+provider+"/complete", body, headers)

                    deadline = time.monotonic()+20
                    while True:
                        if process.poll() is not None: raise RuntimeError("Owned Tomcat exited before readiness")
                        try:
                            if request("GET", "/fixture/health")[0]==200: break
                        except (OSError, http.client.HTTPException): pass
                        if time.monotonic()>=deadline: raise RuntimeError("Bounded Tomcat readiness failed")
                        time.sleep(0.1)
                    check("private-fixture-credential", request("GET", "/fixture/health", authenticated=False)[0]==401)
                    for _ in range(5): check("status-get-does-not-allocate", data(request("GET", "/session"))["authenticated"]=="false")
                    check("status-state-empty", state()["attempts"]==0 and state()["sessions"]==0)
                    check("selected-core-actual-origin", state()["core_origin_verified"] is True)
                    control("admission-deny"); check("admission-before-allocation", begin("google")[0]==429 and state()["attempts"]==0); control("admission-allow")
                    # A cold source proves CSRF rejection precedes even the first provider key fetch.
                    cold = begin("google"); cold_token = token("google", cold)
                    check("cold-csrf-before-provider-work", completion("google", cold, cold_token, csrf="wrong")[0]==403 and state()["google_fetches"]==0 and state()["lookups"]==0)
                    first_google = None
                    for mode in ["valid", "legacy-issuer"]:
                        started = begin("google"); done = completion("google", started, token("google", started, mode))
                        check("google-"+mode+"-real-validation-session", done[0]==200)
                        check("google-session-and-pending-cookies-separate", len(cookies(done))==2 and any(c.startswith("__Host-provider-session=") for c in cookies(done)) and any(c.startswith("__Host-provider-login=;") for c in cookies(done)), len(cookies(done)))
                        check("google-cookie-security-flags", all(all(flag in c for flag in ["Secure","HttpOnly","Path=/"]) for c in cookies(done)))
                        sid = cookie(done,"__Host-provider-session")
                        check("google-authenticated-resource", request("GET", "/account/tenant/alice", headers=[("Cookie",sid)])[0]==200)
                        check("google-wrong-tenant-refused", request("GET", "/account/other/alice", headers=[("Cookie",sid)])[0]==403)
                        check("google-wrong-owner-refused", request("GET", "/account/tenant/bob", headers=[("Cookie",sid)])[0]==403)
                        if first_google is None: first_google = sid
                    for mode in ["wrong-issuer","wrong-audience","wrong-nonce","wrong-presenter","wrong-domain","expired","signature","jku","unmapped"]:
                        started=begin("google"); before=state(); reply=completion("google",started,token("google",started,mode))
                        check("google-hostile-"+mode, reply[0]==(403 if mode=="unmapped" else 401) and state()["sessions"]==before["sessions"], reply[0])
                    check("token-directed-source-never-fetched",state()["attacker_fetches"]==0)
                    for bad in ["duplicate-origin","duplicate-cookie","duplicate-media","duplicate-form","empty-query","wrong-origin","malformed-utf8","encoded-path","header-count","header-value"]:
                        started=begin("google"); compact=token("google",started); before=state()
                        body=encoded({"credential":compact,"g_csrf_token":"TEST-ONLY-csrf"}); path="/google/complete"
                        headers=[*media,("Cookie",cookie(started,"__Host-provider-login")+"; g_csrf_token=TEST-ONLY-csrf")]
                        if bad=="duplicate-origin": headers += origin+origin
                        elif bad=="duplicate-cookie": headers += [("Cookie","g_csrf_token=TEST-ONLY-csrf")]
                        elif bad=="duplicate-media": headers += media
                        elif bad=="duplicate-form": body += b"&g%5Fcsrf_token=TEST-ONLY-csrf"
                        elif bad=="empty-query": path += "?"
                        elif bad=="wrong-origin": headers += [("Origin","https://attacker.invalid")]
                        elif bad=="malformed-utf8": body += b"&unused=%C3%28"
                        elif bad=="encoded-path": path="/google/%63omplete"
                        elif bad=="header-count": headers += [("X-Pad-"+str(n),"x") for n in range(33)]
                        elif bad=="header-value": headers += [("X-Pad","x"*4097)]
                        reply=request("POST",path,body,headers)
                        check(bad+"-refused-before-provider-work",400<=reply[0]<500 and state()["lookups"]==before["lookups"] and state()["sessions"]==before["sessions"],reply[0])
                    # Body-prefix mutant sees a valid form exactly at the cap; the original sees byte cap+1.
                    prefix=b"begin=1"+b"".join(b"&pad"+str(n).encode()+b"="+b"a"*8192 for n in range(1,4))+b"&pad4="
                    prefix+=b"a"*(32768-len(prefix)); assert len(prefix)==32768
                    check("body-exact-cap-control",request("POST","/google/begin",prefix,[*media,*origin],chunked=True)[0]==200)
                    before=state(); oversized=request("POST","/google/begin",prefix+b"&",[*media,*origin],chunked=True)
                    check("chunked-overflow-never-accepted-as-prefix",oversized[0]==413 and state()["attempts"]==before["attempts"],oversized[0])
                    check("declared-body-overflow",request("POST","/google/begin",prefix+b"&",[*media,*origin])[0]==413)
                    before=state()
                    with socket.create_connection(("127.0.0.1",port),timeout=5) as raw:
                        raw.sendall(("POST /providers/google/begin HTTP/1.1\r\nHost: app.example\r\n"
                            +"X-Fixture-Credential: "+credential+"\r\nOrigin: https://app.example\r\n"
                            +"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 50\r\n"
                            +"Connection: close\r\n\r\nbegin=1").encode("ascii"))
                        raw.shutdown(socket.SHUT_WR)
                        truncated=http.client.HTTPResponse(raw); truncated.begin(); truncated.read(65537)
                        check("unavailable-body-never-accepted-as-prefix",truncated.status in (400,503) and state()["attempts"]==before["attempts"],truncated.status)
                    check("head-does-not-complete-or-emit-body",request("HEAD","/google/complete")[0]==405 and request("HEAD","/google/complete")[2]==b"")
                    status=request("GET","/session",headers=[("Cookie",first_google)]); csrf=data(status)["csrf"]
                    rotated_start=begin("google",[("Cookie",first_google)],{"begin":"1","csrf":csrf})
                    rotated=completion("google",rotated_start,token("google",rotated_start)); check("google-rotation-completed",rotated[0]==200)
                    current_cookie=cookie(rotated,"__Host-provider-session")
                    check("google-old-session-revoked",request("GET","/account/tenant/alice",headers=[("Cookie",first_google)])[0]==401)
                    control("deny"); check("current-account-policy-refused",request("GET","/account/tenant/alice",headers=[("Cookie",current_cookie)])[0]==403); control("allow")
                    csrf=data(request("GET","/session",headers=[("Cookie",current_cookie)]))["csrf"]
                    check("browser-logout-csrf",request("POST","/logout",b"csrf=wrong",[*media,*origin,("Cookie",current_cookie)])[0]==403)
                    check("browser-logout-session-ended",request("POST","/logout",encoded({"csrf":csrf}),[*media,*origin,("Cookie",current_cookie)])[0]==200 and request("GET","/account/tenant/alice",headers=[("Cookie",current_cookie)])[0]==401)
                    native_start=begin("apple"); native_token=token("apple",native_start)
                    body=encoded({"request_id":data(native_start)["request_id"],"request_binding":"x"*43,"identity_token":native_token}); before=state()
                    check("native-request-binding-before-provider-work",request("POST","/apple/complete",body,media)[0]==401 and state()["apple_fetches"]==before["apple_fetches"])
                    check("native-rejects-browser-origin",completion("apple",native_start,native_token,origin)[0]==403)
                    check("native-rejects-ambient-cookie",completion("apple",native_start,native_token,[("Cookie","ambient=x")])[0]==403)
                    native_done=completion("apple",native_start,native_token);check("apple-real-validation-session",native_done[0]==200 and not cookies(native_done))
                    sid=data(native_done)["session_token"]; bearer=[("Authorization","Bearer "+sid)]
                    check("apple-resource-authorized",request("GET","/native/account/tenant/alice",headers=bearer)[0]==200)
                    check("apple-provider-token-is-not-api-bearer",request("GET","/native/account/tenant/alice",headers=[("Authorization","Bearer "+native_token)])[0]==401)
                    check("apple-replay-refused",completion("apple",native_start,native_token)[0]==401)
                    for mode in ["wrong-issuer","wrong-audience","wrong-nonce","expired","signature","unmapped"]:
                        started=begin("apple"); done=completion("apple",started,token("apple",started,mode))
                        check("apple-hostile-"+mode,done[0]==(403 if mode=="unmapped" else 401),done[0])
                    race=begin("apple"); compact=token("apple",race); before=state()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                        futures=[workers.submit(completion,"apple",race,compact) for _ in range(2)]
                        outcomes=sorted(f.result(timeout=5)[0] for f in futures)
                    check("native-replay-race-one-winner",outcomes==[200,401] and state()["lookups"]==before["lookups"]+1,outcomes)
                    rotated_start=begin("apple",bearer); rotated=completion("apple",rotated_start,token("apple",rotated_start))
                    check("native-session-rotation",rotated[0]==200 and request("GET","/native/account/tenant/alice",headers=bearer)[0]==401)
                    bearer=[("Authorization","Bearer "+data(rotated)["session_token"])]
                    check("native-local-logout",request("POST","/native/logout",headers=[*media,*bearer])[0]==200 and request("GET","/native/account/tenant/alice",headers=bearer)[0]==401)
                    control("outage"); started=begin("google"); compact=token("google",started); before=state()
                    failed=completion("google",started,compact)
                    check("source-outage-withholds-session-without-retry",failed[0]==503 and state()["google_fetches"]==before["google_fetches"]+1 and state()["lookups"]==before["lookups"] and state()["sessions"]==before["sessions"])
                    check("source-outage-attempt-not-replayed",completion("google",started,compact)[0]==401 and state()["google_fetches"]==before["google_fetches"]+1)
                    receipt["finalState"] = state()
                    receipt["success"] = True
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait(timeout=5)
                    receipt["ownedProcessStopped"] = process.poll() is not None
                else: receipt["ownedProcessStopped"] = True
        receipt["ownedInstanceRemoved"] = not instance.exists()
    except Exception as failure:
        receipt["failure"] = {"checkpoint": current, "type": type(failure).__name__, "message": str(failure)[:300]}
        if instance is not None: receipt["ownedInstanceRemoved"] = not instance.exists()
    finally:
        if not receipt["ownedProcessStopped"] or not receipt["ownedInstanceRemoved"]: receipt["success"] = False
        (args.output/"RESULT.json").write_text(json.dumps(receipt, indent=2)+"\n")
    print(json.dumps({"success":receipt["success"], "checks":len(receipt["checks"]),
                      "failure":receipt.get("failure"), "ownedProcessStopped":receipt["ownedProcessStopped"],
                      "ownedInstanceRemoved":receipt["ownedInstanceRemoved"]}))
    return 0 if receipt["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
