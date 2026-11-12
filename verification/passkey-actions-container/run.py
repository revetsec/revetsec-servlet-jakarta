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

"""Qualify one-use typed WebAuthn action policy through actual paired Servlet application routes."""
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
    parser.add_argument("--scenario",choices=["main","deadline","unknown","reconciliation","capacity"],default="main")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    recipe = args.recipe_source or repo/"docs/ServletPasskeyActionsRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    sources = [recipe,fixture/"PasskeyActionsServlet.java",fixture/"PasskeyActionsFixture.java",repo/"verification/m12-container/M12FaultStore.java"]
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
               "coreJarSha256": args.core_sha256, "adapterJarSha256": args.adapter_sha256, "sourceInputs": inputs, "scenario":args.scenario,"checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Actual public-core/JCA signed synthetic WebAuthn inputs with current local session and one-use action application; pinned Servlet runtime. No physical/browser/TLS/deployment/UTC/durable/final release claim"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-passkey-actions-"+namespace+"-") as directory:
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
                    '<web-app><servlet><servlet-name>saml</servlet-name><servlet-class>example.PasskeyActionsServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>saml</servlet-name>'
                    '<url-pattern>/passkeys/*</url-pattern></servlet-mapping></web-app>')
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
                environment["REVETSEC_PASSKEY_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_PASSKEY_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_PASSKEY_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_PASSKEY_ADAPTER_JAR"] = str(copied_adapter)
                environment["REVETSEC_PASSKEY_ADAPTER_SHA256"] = args.adapter_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, "/passkeys"+path, skip_host=True, skip_accept_encoding=True)
                            connection.putheader("Host", "login.example.com")
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
                                receipt["requests"].append({"method":method,"path":path.partition("?")[0],"queryDelimiterPresent":"?"in path,"querySha256":hashlib.sha256(path.partition("?")[2].encode()).hexdigest(),"status":response.status,
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
                    def cookies(reply): return [v for k,v in reply[1] if k.lower()=="set-cookie"]
                    def cookie(reply,name):
                        found=[v.split(";",1)[0] for v in cookies(reply) if v.startswith(name+"=")]
                        assert len(found)==1,"one-cookie-"+name
                        return found[0]
                    def header(reply,name):
                        found=[v for k,v in reply[1] if k.lower()==name]
                        assert len(found)==1,"one-header-"+name
                        return found[0]
                    def state():return data(request("GET","/fixture/state"))
                    def control(command):
                        value=request("GET","/fixture/"+command);assert value[0]==200,"fixture-control-"+command;return data(value)
                    def encoded(fields):return urllib.parse.urlencode(fields).encode("ascii")
                    origin=[("Origin","https://login.example.com")];json_media=[("Content-Type","application/json")];form_media=[("Content-Type","application/x-www-form-urlencoded")]
                    def bootstrap():
                        reply=request("POST","/session",headers=origin);assert reply[0]==200,"explicit-anonymous-bootstrap";return {"cookie":cookie(reply,"__Host-passkey-actions"),"csrf":data(reply)["csrf"]}
                    def fields(browser,operator=False,extra=()):return [*origin,("Cookie",browser["cookie"]),("X-CSRF-Token",browser["csrf"]),*([("X-Demo-Access-Key","A"*43)]if operator else []),*extra]
                    def login(browser=None):
                        browser=browser or bootstrap();reply=request("POST","/access-login",headers=fields(browser,True));assert reply[0]==200,"independent-operator-account-approval";return {"cookie":cookie(reply,"__Host-passkey-actions"),"csrf":data(reply)["csrf"]}
                    def mint(name,kind,challenge):
                        value=request("POST","/fixture/mint/"+name+"/"+kind,encoded({"challenge":challenge}),form_media);assert value[0]==200,"genuine-JCA-authenticator-input";return data(value)
                    def options(browser,path,operator=False,target=None):
                        extra=[]if target is None else[("X-Credential-Id",target)];reply=request("POST",path,headers=fields(browser,operator,extra));assert reply[0]==200,"core-prepared-browser-options";value=data(reply);assert len(value["ceremonyId"])==43 and len(value["publicKey"]["challenge"])==43,"core-ceremony-challenge";return value
                    def finish(browser,path,prepared,name="one",operator=False,body=None,extra=()):
                        minted=mint(name,"register"if path=="/register/finish"else"assert",prepared["publicKey"]["challenge"]);payload=body if body is not None else __import__('base64').b64decode(minted["body"])
                        return request("POST",path,payload,fields(browser,operator,[*json_media,("X-Ceremony-Id",prepared["ceremonyId"]),*extra]))
                    def register(browser,name):
                        prepared=options(browser,"/register/start",True);reply=finish(browser,"/register/finish",prepared,name,True);assert reply[0]==200,"genuine-registration";return mint(name,"assert",prepared["publicKey"]["challenge"])["credential_id"]
                    def sensitive(browser):return request("POST","/sensitive",headers=fields(browser))
                    def reauth(browser,path="/reauth/start",target=None):return options(browser,path,target=target)
                    def approved(browser,prepared=None):
                        prepared=prepared or reauth(browser);return finish(browser,"/reauth/finish",prepared)
                    def grants():return state()["raw"]["grants"]
                    deadline=time.monotonic()+15
                    while time.monotonic()<deadline:
                        if process.poll()is not None:raise RuntimeError("Owned Tomcat exited before readiness")
                        try:
                            if request("GET","/fixture/state")[0]==200:break
                        except(OSError,http.client.HTTPException):pass
                        time.sleep(.05)
                    else:raise RuntimeError("Owned Tomcat readiness failed")
                    check("selected-artifact-origins-and-runtime",state()["origin_verified"],state()["java_version"])
                    if args.scenario=="deadline":
                        check("wrap-safe-grant-duration",control("deadline-wrap")["duration"]==60_000_000_000)
                    else:
                        check("fixture-control-credential",request("GET","/fixture/state",authenticated=False)[0]==401)
                        check("get-does-not-allocate-session",data(request("GET","/session"))["authenticated"]is False and state()["raw"]["sessions"]==0)
                        check("wrong-origin-bootstrap-denied",request("POST","/session",headers=[("Origin","https://wrong.invalid")])[0]==403)
                        browser=bootstrap();old=browser;browser=login(browser);check("independent-approval-rotates-session",old["cookie"]!=browser["cookie"] and data(request("GET","/session",headers=[("Cookie",old["cookie"])]))["authenticated"]is False)
                        check("unapproved-sensitive-denied",sensitive(browser)[0]==403)
                        one=register(browser,"one");two=register(browser,"two");check("two-real-credentials-registered",one!=two)
                        listed=request("POST","/credentials/list",headers=fields(browser));check("actual-account-credential-list",listed[0]==200 and set(data(listed)["credentialIds"])=={one,two})
                        if args.scenario in["unknown","reconciliation"]:
                            step=reauth(browser);before=state();control("store-"+args.scenario);reply=approved(browser,step);after=state()
                            check("actual-core-effect-withheld-"+args.scenario,reply[0]==503 and after["store_effects"]==before["store_effects"]+1 and grants()==0,reply[0])
                            check("admission-closed-without-retry-"+args.scenario,after["application"]["admission_open"]is False and sensitive(browser)[0]==503 and state()["store_effects"]==after["store_effects"])
                            if args.scenario=="reconciliation":check("known-commit-final-clock-refusal",after["store_final_reads"]==before["store_final_reads"]+1)
                        elif args.scenario=="capacity":
                            initial=state()["raw"]["sessions"]
                            for unused in range(64-initial):bootstrap()
                            before=state();reply=request("POST","/session",headers=origin);check("capacity-no-live-eviction",reply[0]==503 and state()["raw"]["sessions"]==64 and data(request("GET","/session",headers=[("Cookie",browser["cookie"])]))["authenticated"]is True)
                            control("clock-expire-session");check("expired-entry-cleanup-exact-count",state()["raw"]["sessions"]==0)
                            control("clock-normal");check("new-session-after-expiry",bootstrap()and state()["raw"]["sessions"]==1)
                        else:
                            # General SIGN_IN remains separate from the restricted reauthentication proof.
                            anonymous=bootstrap();start=options(anonymous,"/sign-in/start");signed=finish(anonymous,"/sign-in/finish",start);check("genuine-general-sign-in",signed[0]==200);browser={"cookie":cookie(signed,"__Host-passkey-actions"),"csrf":data(signed)["csrf"]}
                            step=reauth(browser);reply=approved(browser,step);check("typed-reauth-creates-one-local-grant",reply[0]==200 and grants()==1)
                            check("one-use-sensitive-action",sensitive(browser)[0]==200 and sensitive(browser)[0]==403 and grants()==0)
                            check("completed-ceremony-replay-no-grant",approved(browser,step)[0]in[400,403]and grants()==0)
                            step=reauth(browser);before=state();other=login();reply=finish(other,"/reauth/finish",step);check("wrong-session-before-proof-no-grant",reply[0]==403 and grants()==0)
                            check("original-session-still-can-complete",approved(browser,step)[0]==200 and sensitive(browser)[0]==200)
                            # An owned but different target still consumes and denies the selected grant.
                            step=reauth(browser,"/credentials/self-remove/start",two);assert finish(browser,"/credentials/self-remove/finish",step,"one")[0]==200
                            wrong=request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",one)]));check("different-owned-target-denies-and-burns",wrong[0]==403 and request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",two)]))[0]==403)
                            # The signing credential differs from the separately approved removal target.
                            step=reauth(browser,"/credentials/self-remove/start",two);reply=finish(browser,"/credentials/self-remove/finish",step,"one")
                            check("different-authenticating-key-can-approve-owned-target",reply[0]==200 and grants()==1)
                            removed=request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",two)]));check("target-bound-self-removal-once",removed[0]==200 and request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",two)]))[0]==403)
                            listed=request("POST","/credentials/list",headers=fields(browser));check("real-removal-effect-in-authoritative-list",data(listed)["credentialIds"]==[one])
                            step=reauth(browser);assert approved(browser,step)[0]==200;wrong=request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",one)]));check("wrong-action-burns-one-use-slot",wrong[0]==403 and sensitive(browser)[0]==403)
                            check("stepup-not-operator-management",request("POST","/credentials/remove",headers=fields(browser,False,[("X-Credential-Id",one)]))[0]==403)
                            for variant in ["namespace","rp","account","purpose","ceremony","pending"]:
                                value=request("GET","/fixture/proof/"+variant);check("genuine-typed-proof-context-"+variant,value[0]==200 and data(value)["genuine_core_proof"]and data(value)["accepted"]is False)
                            value=request("GET","/fixture/proof/valid");check("genuine-typed-proof-positive-join",value[0]==200 and data(value)["accepted"]is True)
                            value=request("GET","/fixture/proof/foreign-owner");check("foreign-app-cannot-burn-genuine-grant",value[0]==200 and data(value)["genuine_core_proof"]and data(value)["foreign_burn_preserved"])
                            # Raw carrier controls precede any core mutation; they cannot mint local authority.
                            untouched=state()["store_effects"]
                            for name,path,body,extra in [
                                ("bare-query","/reauth/start?",b"",[]),("query","/reauth/start?x=1",b"",[]),
                                ("encoded-path","/%72eauth/start",b"",[]),
                                ("duplicate-csrf","/reauth/start",b"",[("X-CSRF-Token",browser["csrf"])]),
                                ("duplicate-cookie","/reauth/start",b"",[("Cookie",browser["cookie"])]),
                                ("cookie-name-ambiguity","/reauth/start",b"",[("Cookie","other=x; other=y")]),
                                ("bearer-rejected","/reauth/start",b"",[("Authorization","Bearer untrusted")]),
                                ("forwarded-rejected","/reauth/start",b"",[("Forwarded","proto=https")]),
                                ("empty-route-extra-byte","/reauth/start",b"x",[])]:
                                reply=request("POST",path,body,fields(browser,False,extra));check("raw-carrier-"+name,reply[0]==400 and state()["store_effects"]==untouched and grants()==0,reply[0])
                            missing=request("POST","/reauth/start",headers=[*origin,("Cookie",browser["cookie"])]);check("missing-csrf-before-core",missing[0]==400 and state()["store_effects"]==untouched)
                            step=reauth(browser);base=state()["store_effects"]
                            for name,body,extra,chunked in [("declared-over-cap",b"x"*65537,json_media,False),("chunked-over-cap",b"x"*65537,json_media,True),("wrong-media",b"{}",form_media,False),("duplicate-media",b"{}",[*json_media,*json_media],False)]:
                                reply=request("POST","/reauth/finish",body,fields(browser,False,[*extra,("X-Ceremony-Id",step["ceremonyId"])]),chunked=chunked);check("body-bound-"+name,reply[0]==400 and state()["store_effects"]==base and grants()==0,reply[0])
                            check("bounded-body-refusals-preserve-genuine-pending",approved(browser,step)[0]==200)
                            before=state()["application"]["sensitive_effects"]
                            with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:responses=list(pool.map(lambda unused:sensitive(browser),range(2)))
                            check("two-concurrent-one-use-one-effect",sorted(r[0]for r in responses)==[200,403]and state()["application"]["sensitive_effects"]==before+1 and grants()==0)
                            # Eight original operations occupy all host permits before store/key work.
                            control("store-block-reads")
                            with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
                                waiting=[pool.submit(request,"POST","/reauth/start",headers=fields(browser))for unused in range(8)];until=time.monotonic()+2
                                while state()["read_entered"]<8 and time.monotonic()<until:time.sleep(.01)
                                before=state();check("eight-admitted-store-reads-observed",before["read_entered"]==8 and before["read_peak"]==8)
                                ninth=request("POST","/reauth/start",headers=fields(browser));check("ninth-refused-before-store-work",ninth[0]==503 and state()["read_entered"]==8)
                                control("release");replies=[pending.result(timeout=5)for pending in waiting]
                            check("eight-admitted-original-operations-complete",all(reply[0]==200 for reply in replies),[reply[0]for reply in replies])
                            # The store delay happens AFTER a genuine known commit and outside its monitor.
                            first=reauth(browser);control("store-pause-completion")
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                                pending=pool.submit(approved,browser,first);until=time.monotonic()+2
                                while not state()["store_blocked"]and time.monotonic()<until:time.sleep(.01)
                                check("genuine-completion-commit-observed-blocked",state()["store_blocked"])
                                newer=reauth(browser);control("release");old=pending.result(timeout=5)
                            check("replaced-pending-cannot-publish-old-proof",old[0]==403 and grants()==0,old[0]);check("new-pending-survives-old-continuation",approved(browser,newer)[0]==200 and sensitive(browser)[0]==200)
                            first=reauth(browser);control("store-pause-completion")
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                                pending=pool.submit(approved,browser,first);until=time.monotonic()+2
                                while not state()["store_blocked"]and time.monotonic()<until:time.sleep(.01)
                                check("genuine-core-work-blocked-before-logout",state()["store_blocked"])
                                oldbrowser=browser;loggedout=request("POST","/logout",headers=fields(browser));assert loggedout[0]==200
                                anonymous={"cookie":cookie(loggedout,"__Host-passkey-actions"),"csrf":data(loggedout)["csrf"]};control("release");old=pending.result(timeout=5)
                            check("logout-during-core-work-never-publishes",old[0]==403 and grants()==0 and sensitive(oldbrowser)[0]==403 and sensitive(anonymous)[0]==403,old[0]);browser=login(anonymous)
                            # Old completion refusal must not erase a newer exact grant.
                            for mode,flag in [("writer-block-throw","writer_blocked"),("close-block","gate_blocked")]:
                                first=reauth(browser);control(mode)
                                with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                                    pending=pool.submit(approved,browser,first);until=time.monotonic()+2
                                    while not state()[flag]and time.monotonic()<until:time.sleep(.01)
                                    check("old-output-observed-blocked-"+mode,state()[flag])
                                    later=reauth(browser);check("newer-grant-published-"+mode,approved(browser,later)[0]==200 and grants()==1)
                                    control("release");old=pending.result(timeout=5)
                                check("old-refusal-preserves-newer-grant-"+mode,old[0]==503 and grants()==1 and sensitive(browser)[0]==200 and sensitive(browser)[0]==403)
                            # Local logout fences a completion already holding its old Session object.
                            first=reauth(browser);control("close-block")
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                                pending=pool.submit(approved,browser,first);until=time.monotonic()+2
                                while not state()["gate_blocked"]and time.monotonic()<until:time.sleep(.01)
                                check("completion-blocked-before-local-logout",state()["gate_blocked"])
                                oldbrowser=browser;loggedout=request("POST","/logout",headers=fields(browser));assert loggedout[0]==200
                                anonymous={"cookie":cookie(loggedout,"__Host-passkey-actions"),"csrf":data(loggedout)["csrf"]};control("release");late=pending.result(timeout=5)
                            check("logout-cancels-late-proof-authority",late[0]==503 and sensitive(oldbrowser)[0]==403 and sensitive(anonymous)[0]==403 and grants()==0)
                            browser=login(anonymous)
                            # Every observed writer/final-gate failure burns only this new grant.
                            for fault in ["writer-runtime","writer-throw","writer-clock-throw","close-throw","close-expire","close-clock-throw","final-stale","close-interrupt"]:
                                step=reauth(browser);attempts=state()["writer_attempts"];control(fault)
                                try:reply=approved(browser,step)
                                except(OSError,http.client.HTTPException)as transport:
                                    if fault!="close-interrupt":raise
                                    receipt["injectedInterruptTransportLimit"]=type(transport).__name__;reply=(0,[],b"")
                                if fault=="writer-runtime":check("runtime-writer-no-second-app-output",state()["writer_attempts"]==attempts+1)
                                check("withheld-approval-no-permission-"+fault,reply[0]in([0,503]if fault=="close-interrupt"else[503])and grants()==0,reply[0]);control("clock-normal");check("no-grant-revival-after-"+fault,sensitive(browser)[0]==403)
                                if fault=="close-interrupt":check("explicit-injected-interruption-preserved-before-fixture-clear",state()["interruption_observed"]and state()["interrupt_no_grant"])
                                if fault in["writer-clock-throw","close-clock-throw"]:check("clock-failure-cannot-prevent-exact-burn-"+fault,state()["burn_without_clock"])
                            # Explicit operator route is separate from, and cannot be substituted by, step-up.
                            removed=request("POST","/credentials/remove",headers=fields(browser,True,[("X-Credential-Id",one)]));check("independent-operator-removal",removed[0]==200)
                            check("operator-effect-real-account-now-empty",data(request("POST","/credentials/list",headers=fields(browser)))["credentialIds"]==[])
                            control("clock-expire-session");check("session-exact-expiry-denies-authority",data(request("GET","/session",headers=[("Cookie",browser["cookie"])]))["authenticated"]is False and sensitive(browser)[0]==403)
                            control("clock-normal");check("expired-session-non-revival-on-wall-rollback",data(request("GET","/session",headers=[("Cookie",browser["cookie"])]))["authenticated"]is False and sensitive(browser)[0]==403)
                    receipt["finalState"]=state();assert all(digest(Path(path))==value for path,value in inputs.items()),"Qualification source changed";receipt["sourceStable"]=True;receipt["success"]=True
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
