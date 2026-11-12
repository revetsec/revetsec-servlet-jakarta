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

"""Qualify the complete paired S2 resource/acquisition host in owned pinned Tomcat."""
import argparse
import concurrent.futures
import hashlib
import http.client
import html.parser
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
    parser.add_argument("--adapter-jar", type=Path, required=True)
    parser.add_argument("--adapter-sha256", required=True)
    parser.add_argument("--recipe-source", type=Path, help="Private carrier calibration override; recorded by exact digest")
    parser.add_argument("--annotations-repository", type=Path, default=Path.home()/".m2/repository")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    recipe = args.recipe_source or repo/"docs/ServletResourceServerRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    sources = [recipe, fixture/"ResourceServerServlet.java", fixture/"ResourceServerFixture.java"]
    auditor = repo/"verification/nullability/NullabilityAudit.java"
    for item in [args.tomcat_archive, args.core_jar, args.adapter_jar, *annotations, *sources, auditor, pins_path]:
        if not item.is_file(): parser.error("Required input missing: "+str(item))
    if not re.fullmatch("[0-9a-f]{64}", args.core_sha256) or digest(args.core_jar) != args.core_sha256:
        parser.error("Selected core SHA256 mismatch before instance creation")
    if not re.fullmatch("[0-9a-f]{64}", args.adapter_sha256) or digest(args.adapter_jar) != args.adapter_sha256:
        parser.error("Selected adapter SHA256 mismatch before instance creation")
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive differs from reviewed SHA512")
    if args.output.exists(): parser.error("Use a fresh evidence output directory")
    inputs = {str(p.resolve()): digest(p) for p in [*sources, auditor, pins_path, Path(__file__)]}
    receipt = {"namespace": namespace, "runtime": pins["version"], "runtimeSha512": pins["archiveSha512"],
               "coreJarSha256": args.core_sha256, "adapterJarSha256": args.adapter_sha256, "sourceInputs": inputs, "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Synthetic AS/JWKS/introspection/read-onlybackend/account collaborators; real Servlet container; no real service/TLS/deployment/formal S2 tool pass claim"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-resource-"+namespace+"-") as directory:
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
                copied_adapter=base/"webapps/ROOT/WEB-INF/lib/adapter.jar"
                shutil.copyfile(args.adapter_jar,copied_adapter)
                if digest(copied_adapter)!=args.adapter_sha256:raise RuntimeError("Selected adapter changed during copy")
                classpath = os.pathsep.join(map(str, [args.core_jar, args.adapter_jar, home/"lib/servlet-api.jar", *annotations]))
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
                    '<web-app><servlet><servlet-name>oidc</servlet-name><servlet-class>example.ResourceServerServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>oidc</servlet-name>'
                    '<url-pattern>/jwt/*</url-pattern></servlet-mapping><servlet-mapping><servlet-name>oidc</servlet-name><url-pattern>/opaque/*</url-pattern></servlet-mapping></web-app>')
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
                # Fixed loopback fixture trust only: secure=true is not a real TLS handshake qualification.
                (base/"conf/server.xml").write_text(
                    f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}"'
                    ' protocol="HTTP/1.1" scheme="https" secure="true" connectionTimeout="2000"'
                    ' disableUploadTimeout="false" connectionUploadTimeout="2000" maxHttpRequestHeaderSize="16384"'
                    ' maxHeaderCount="64" maxParameterCount="32" maxPostSize="70000" maxSwallowSize="70000"'
                    ' maxConnections="32" maxThreads="16" acceptCount="16"/><Engine name="fixture" defaultHost="localhost">'
                    '<Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/>'
                    '</Engine></Service></Server>')
                credential = secrets.token_urlsafe(32)
                environment = dict(os.environ)
                environment.pop("JAVA_TOOL_OPTIONS", None); environment.pop("JDK_JAVA_OPTIONS", None)
                environment["REVETSEC_RESOURCE_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_RESOURCE_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_RESOURCE_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_RESOURCE_ADAPTER_JAR"] = str(copied_adapter)
                environment["REVETSEC_RESOURCE_ADAPTER_SHA256"] = args.adapter_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False, profile="jwt",host="api.example"):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, "/"+profile+path, skip_host=True, skip_accept_encoding=True)
                            connection.putheader("Host", host)
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
                                receipt["requests"].append({"method":method,"path":path.partition("?")[0],"querySha256":hashlib.sha256(path.partition("?")[2].encode()).hexdigest(),"status":response.status,
                                    "bodySha256":hashlib.sha256(payload).hexdigest(),
                                    "cookieCount":sum(name.lower()=="set-cookie" for name,value in fields)})
                            return response.status, fields, payload
                        finally: connection.close()

                    def check(name, condition, observed=None):
                        nonlocal current
                        current = name
                        receipt["checks"].append({"name": name, "passed": bool(condition), "observed": observed})
                        assert condition, name

                    def data(reply):return json.loads(reply[2])
                    def header(reply,name):return [value for field,value in reply[1] if field.lower()==name]
                    def state():return data(request("GET","/fixture/state"))
                    def control(command,token=None):return request("GET","/fixture/"+command,headers=[] if token is None else [("X-Fixture-Token",token)])
                    def mint(profile="jwt",mutation="valid"):
                        reply=request("GET","/fixture/mint/"+profile+"/"+mutation);assert reply[0]==200,"private-token-fixture"
                        return data(reply)["token"]
                    def api(profile,token,route="/accounts/tenant/alice",proxy=False,extra=(),body=None,method=None,chunked=False,host="api.example"):
                        fields=[] if token is None else [("Authorization","Bearer "+token)]
                        if proxy:fields.append(("Content-Type","application/x-www-form-urlencoded"));route+="/proxy-read"
                        return request(method or ("POST" if proxy else "GET"),route,body if body is not None else b"read=1" if proxy else b"",[*fields,*extra],chunked=chunked,profile=profile,host=host)
                    def private_error(reply,token=None):
                        return not header(reply,"set-cookie") and not header(reply,"location") and b"protected-" not in reply[2] and b"TEST-ONLY" not in reply[2] and (token is None or token.encode() not in reply[2])
                    def infrastructure(reply):return reply[0]==503 and not header(reply,"www-authenticate") and private_error(reply)
                    def wait_blocked(count=1):
                        deadline=time.monotonic()+1
                        while True:
                            if state()["blocked_count"]==count:return
                            if time.monotonic()>=deadline:raise AssertionError("bounded-fixture-block-observation")
                            time.sleep(0.01)
                    deadline=time.monotonic()+20
                    while True:
                        if process.poll() is not None:raise RuntimeError("Owned Tomcat exited before readiness")
                        try:
                            if request("GET","/fixture/state")[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>=deadline:raise RuntimeError("Bounded Tomcat readiness failed")
                        time.sleep(0.1)
                    check("private-fixture-gate",request("GET","/fixture/state",authenticated=False)[0]==401)
                    check("actual-core-and-adapter-origins",state()["origin_verified"] is True)
                    for profile in ["jwt","opaque"]:
                        compact=mint(profile)
                        for bad in ["missing","malformed","duplicate","cookie","query","body-token","wrong-origin","wrong-host","get-body","headers","encoded-path","body-overflow","chunked-overflow","duplicate-media","invalid-form","method","head"]:
                            before=state()
                            if bad=="missing":reply=api(profile,None)
                            elif bad=="malformed":reply=request("GET","/accounts/tenant/alice",headers=[("Authorization","Basic wrong")],profile=profile)
                            elif bad=="duplicate":reply=api(profile,compact,extra=[("Authorization","Bearer "+compact)])
                            elif bad=="cookie":reply=api(profile,compact,extra=[("Cookie","ambient=session")])
                            elif bad=="query":reply=api(profile,compact,route="/accounts/tenant/alice?access_token="+compact)
                            elif bad=="body-token":reply=api(profile,compact,proxy=True,body=b"read=1&access_token=ignored")
                            elif bad=="wrong-origin":reply=api(profile,compact,extra=[("Origin","https://attacker.invalid")])
                            elif bad=="wrong-host":reply=api(profile,compact,host="attacker.invalid")
                            elif bad=="get-body":reply=api(profile,compact,body=b"unexpected")
                            elif bad=="headers":reply=api(profile,compact,extra=[("X-Pad-"+str(n),"x") for n in range(33)])
                            elif bad=="body-overflow":reply=api(profile,compact,proxy=True,body=b"read=1"+b"a"*123)
                            elif bad=="chunked-overflow":reply=api(profile,compact,proxy=True,body=b"read=1"+b"a"*123,chunked=True)
                            elif bad=="duplicate-media":reply=api(profile,compact,proxy=True,extra=[("Content-Type","application/x-www-form-urlencoded")])
                            elif bad=="invalid-form":reply=api(profile,compact,proxy=True,body=b"r%65ad=1")
                            elif bad=="method":reply=api(profile,compact,method="PUT")
                            elif bad=="head":reply=api(profile,compact,method="HEAD")
                            else:reply=api(profile,compact,route="/accounts/tenant/%61lice")
                            after=state();expected=401 if bad=="missing" else 403 if bad=="wrong-origin" else 413 if bad in ["body-overflow","chunked-overflow"] else 405 if bad in ["method","head"] else 400
                            check(profile+"-raw-carrier-"+bad,reply[0]==expected and private_error(reply,compact) and all(after[name]==before[name] for name in ["key_calls","introspection_calls","acquisition_calls","lookups","data_reads","backend_calls"]),reply[0])
                            if bad in ["malformed","duplicate"]:check(profile+"-malformed-bearer-challenge",any('error="invalid_request"' in value for value in header(reply,"www-authenticate")))
                    check("cold-raw-refusals-before-provider-work",state()["key_calls"]==0 and state()["introspection_calls"]==0 and state()["basic_checks"]==0)
                    for profile in ["jwt","opaque"]:
                        compact=mint(profile);before=state();reply=api(profile,compact)
                        check(profile+"-actual-credential-and-resource",reply[0]==200 and data(reply)=={"tenant":"tenant","account":"alice","value":"protected-alice-v1"},reply[0])
                        check(profile+"-private-success-envelope",header(reply,"cache-control")==["no-store"] and not header(reply,"set-cookie") and not header(reply,"www-authenticate") and compact.encode() not in reply[2])
                        if profile=="opaque":
                            check("authenticated-introspection-form-and-basic",state()["introspection_calls"]==before["introspection_calls"]+1 and state()["basic_checks"]==before["basic_checks"]+1)
                            before=state();check("opaque-credential-not-cached",api(profile,compact)[0]==200 and state()["introspection_calls"]==before["introspection_calls"]+1)
                            control("revoke-opaque",compact);before=state();revoked=api(profile,compact)
                            check("revoked-opaque-checked-on-every-request",revoked[0]==401 and any('error="invalid_token"' in value for value in header(revoked,"www-authenticate")) and state()["introspection_calls"]==before["introspection_calls"]+1 and state()["data_reads"]==before["data_reads"],revoked[0])
                        bob=mint(profile,"bob");before=state()
                        check(profile+"-second-real-account-row",api(profile,bob,route="/accounts/other/bob")[0]==200)
                        denied=api(profile,compact,route="/accounts/other/bob")
                        if profile=="opaque":denied=api(profile,mint(profile),route="/accounts/other/bob")
                        check(profile+"-cross-tenant-object-denied",denied[0]==403 and private_error(denied),denied[0])
                        check(profile+"-other-account-cannot-read-alice",api(profile,bob)[0]==403)
                        before=state();reply=api(profile,mint(profile),route="/accounts/tenant/bob")
                        check(profile+"-route-other-owner-denied-before-data",reply[0]==403 and state()["data_reads"]==before["data_reads"],reply[0])
                    for profile in ["jwt","opaque"]:
                        for mutation in ["wrong-issuer","wrong-audience","multi-audience","expired","future-issued","wrong-scope","missing-tenant","nonstring-tenant","wrong-tenant","unmapped","wrong-client"]:
                            compact=mint(profile,mutation);before=state();reply=api(profile,compact)
                            expected=403 if mutation in ["wrong-scope","wrong-tenant","unmapped","wrong-client"] else 401
                            check(profile+"-profile-"+mutation,reply[0]==expected and private_error(reply,compact) and state()["data_reads"]==before["data_reads"] and state()["backend_calls"]==before["backend_calls"],reply[0])
                            if mutation=="wrong-scope":check(profile+"-insufficient-scope-challenge",any('error="insufficient_scope"' in value for value in header(reply,"www-authenticate")))
                        read_only=mint(profile,"read-only");before=state();refused=api(profile,read_only,proxy=True)
                        check(profile+"-proxy-scope-before-acquisition",refused[0]==403 and state()["acquisition_calls"]==before["acquisition_calls"] and state()["backend_calls"]==before["backend_calls"])
                    check("jwt-identity-token-profile-refused",api("jwt",mint("jwt","identity-type"))[0]==401)
                    check("jwt-invalid-signature-refused",api("jwt",mint("jwt","signature"))[0]==401)
                    check("opaque-authority-can-omit-issuer",api("opaque",mint("opaque","omit-issuer"))[0]==200)
                    check("jwt-missing-issuer-not-accepted",api("jwt",mint("jwt","omit-issuer"))[0]==401)
                    before=state();opaque=mint("opaque");wrong=api("jwt",opaque)
                    check("jwt-mode-has-no-opaque-fallback",wrong[0]==401 and state()["introspection_calls"]==before["introspection_calls"])
                    jwt=mint("jwt");before=state();wrong=api("opaque",jwt)
                    check("opaque-mode-is-fixed-authenticated-introspection",wrong[0]==401 and state()["introspection_calls"]==before["introspection_calls"]+1)
                    compact=mint();control("admission-deny");before=state();refused=api("jwt",compact);control("admission-allow")
                    check("abuse-admission-before-validation",refused[0]==429 and state()["key_calls"]==before["key_calls"] and state()["lookups"]==before["lookups"])
                    for command,proxy,counter in [("deny",False,"data_reads"),("deny-read",False,"data_reads"),("deny-proxy",True,"backend_calls")]:
                        compact=mint();before=state();control(command);refused=api("jwt",compact,proxy=proxy);control("allow" if command=="deny" else "allow-read" if command=="deny-read" else "allow-proxy")
                        check(command+"-before-protected-operation",refused[0]==403 and state()[counter]==before[counter] and state()["acquisition_calls"]==before["acquisition_calls"],refused[0])
                    compact=mint();before=state();proxy=api("jwt",compact,proxy=True)
                    check("actual-fixed-policy-client-credentials-and-read-only-use",proxy[0]==200 and state()["acquisition_calls"]==before["acquisition_calls"]+1 and state()["backend_authorized"]==before["backend_authorized"]+1 and state()["basic_checks"]==before["basic_checks"]+1,proxy[0])
                    before=state();second=api("opaque",mint("opaque"),proxy=True)
                    check("valid-service-token-cache-shared-only-fixed-policy",second[0]==200 and state()["acquisition_calls"]==before["acquisition_calls"] and state()["backend_authorized"]==before["backend_authorized"]+1)
                    compact=mint();before=state();control("reject-backend");refused=api("jwt",compact,proxy=True)
                    check("backend401-is-not-caller-invalid-token-and-is-not-retried",infrastructure(refused) and state()["backend_calls"]==before["backend_calls"]+1 and state()["acquisition_calls"]==before["acquisition_calls"],refused[0])
                    recovered=api("jwt",compact,proxy=True)
                    check("exact-rejected-acquired-instance-is-invalidated",recovered[0]==200 and state()["backend_calls"]==before["backend_calls"]+2 and state()["acquisition_calls"]==before["acquisition_calls"]+1,recovered[0])
                    for profile in ["jwt","opaque"]:
                        compact=mint(profile);before=state();control("block-data")
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                            future=worker.submit(api,profile,compact)
                            try:wait_blocked();control("generation")
                            finally:control("release")
                            refused=future.result(timeout=5)
                        check(profile+"-generation-change-while-read-withholds-data",refused[0]==403 and private_error(refused,compact) and state()["data_reads"]==before["data_reads"]+1,refused[0])
                        check(profile+"-fresh-generation-can-authorize",api(profile,compact)[0]==200)
                    compact=mint();control("block-backend");before=state()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                        future=worker.submit(api,"jwt",compact,"/accounts/tenant/alice",True)
                        try:wait_blocked();control("deny")
                        finally:control("release")
                        refused=future.result(timeout=5)
                    control("allow");check("revocation-during-read-only-backend-withholds-data",refused[0]==403 and private_error(refused,compact) and state()["backend_authorized"]==before["backend_authorized"]+1,refused[0])
                    for profile in ["jwt","opaque"]:
                        compact=mint(profile,"edge-expiry");control("block-data");before=state()
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                            future=worker.submit(api,profile,compact)
                            try:wait_blocked();control("advance-one")
                            finally:control("release")
                            refused=future.result(timeout=5)
                        check(profile+"-exact-expiry-after-data-refuses-output",refused[0]==401 and private_error(refused,compact) and state()["data_reads"]==before["data_reads"]+1,refused[0])
                    compact=mint("jwt","edge-expiry");control("block-backend");before=state()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                        future=worker.submit(api,"jwt",compact,"/accounts/tenant/alice",True)
                        try:wait_blocked();control("advance-one")
                        finally:control("release")
                        refused=future.result(timeout=5)
                    check("exact-caller-expiry-after-backend-withholds-data",refused[0]==401 and private_error(refused,compact) and state()["backend_authorized"]==before["backend_authorized"]+1,refused[0])
                    for mode in ["late","interrupt"]:
                        compact=mint();before=state();control("lookup-"+mode);refused=api("jwt",compact)
                        check("cancelled-or-late-account-work-"+mode,infrastructure(refused) and state()["data_reads"]==before["data_reads"] and state()["backend_calls"]==before["backend_calls"],refused[0])
                        if mode=="interrupt":check("injected-interrupt-recorded-before-fixture-clear",state()["injected_interrupt_observed"] and state()["handler_interrupt_left_set"] and state()["handler_cancel_no_protected_output"])
                    for profile in ["jwt","opaque"]:
                        compact=mint(profile);control("block-data")
                        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                            pending=[workers.submit(api,profile,compact) for _ in range(8)]
                            try:
                                wait_blocked(8);before=state();busy=api(profile,compact)
                                check(profile+"-ninth-operation-refused-before-expensive-work",busy[0]==503 and all(state()[name]==before[name] for name in ["key_calls","introspection_calls","lookups","data_reads"]),busy[0])
                            finally:control("release")
                            completed=[future.result(timeout=5) for future in pending]
                        check(profile+"-work-permits-returned",all(reply[0]==200 for reply in completed) and api(profile,compact)[0]==200)
                    for profile in ["jwt","opaque"]:
                        compact=mint(profile);before=state();control("lookup-expire");refused=api(profile,compact)
                        check(profile+"-expiry-after-account-prevents-data-read",refused[0]==401 and state()["data_reads"]==before["data_reads"] and state()["backend_calls"]==before["backend_calls"],{"status":refused[0],"data_reads_before":before["data_reads"],"data_reads_after":state()["data_reads"],"backend_calls_before":before["backend_calls"],"backend_calls_after":state()["backend_calls"]})
                    compact=mint();control("acquisition-unavailable");compact=mint();before=state();refused=api("jwt",compact,proxy=True)
                    check("expired-service-token-cannot-fallback-during-outage",infrastructure(refused) and state()["acquisition_calls"]==before["acquisition_calls"]+1 and state()["backend_calls"]==before["backend_calls"],refused[0])
                    compact=mint("opaque");control("introspection-unauthorized");before=state();refused=api("opaque",compact)
                    check("introspection401-is-infrastructure-not-caller-verdict",infrastructure(refused) and state()["introspection_calls"]==before["introspection_calls"]+1,refused[0])
                    before=state();blocked=api("opaque",compact)
                    check("introspection-failure-health-no-automatic-retry",infrastructure(blocked) and state()["introspection_calls"]==before["introspection_calls"],blocked[0])
                    compact=mint();control("keys-unavailable");before=state();refused=api("jwt",compact)
                    check("jwt-key-outage-does-not-fallback-to-introspection",infrastructure(refused) and state()["key_calls"]==before["key_calls"]+1 and state()["introspection_calls"]==before["introspection_calls"],refused[0])
                    receipt["finalState"]=state();receipt["success"]=True
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
