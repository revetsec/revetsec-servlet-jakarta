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

"""Qualify the complete paired single-process S1 OIDC RP host in owned pinned Tomcat."""
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
    recipe = args.recipe_source or repo/"docs/ServletOidcRpRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    sources = [recipe, fixture/"OidcRpServlet.java", fixture/"OidcProviderFixture.java"]
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
               "scope": "Synthetic OP/JWKS/account collaborators; real Servlet container; no real browser/TLS/OP, distributed store or formal S1 tool pass claim"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-oidc-rp-"+namespace+"-") as directory:
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
                    '<web-app><servlet><servlet-name>oidc</servlet-name><servlet-class>example.OidcRpServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>oidc</servlet-name>'
                    '<url-pattern>/oidc/*</url-pattern></servlet-mapping></web-app>')
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
                environment["REVETSEC_OIDC_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_OIDC_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_OIDC_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_OIDC_ADAPTER_JAR"] = str(copied_adapter)
                environment["REVETSEC_OIDC_ADAPTER_SHA256"] = args.adapter_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, "/oidc"+path, skip_host=True, skip_accept_encoding=True)
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
                    def state():
                        value=data(request("GET","/fixture/state"));value.update(value.pop("host"))
                        expected=86*value["sessions"]+11*value["authenticated_sessions"]+43*value["pending_sessions"]+215*value["attempts"]
                        assert value["state_bytes"]==expected,"independent-state-string-byte-oracle"
                        return value
                    def control(command): return request("GET","/fixture/"+command)
                    def encoded(fields): return urllib.parse.urlencode(fields).encode("ascii")
                    media=[("Content-Type","application/x-www-form-urlencoded")]
                    origin=[("Origin","https://app.example")]
                    def bootstrap():
                        reply=request("POST","/session",b"begin=1",[*media,*origin]);assert reply[0]==200,"explicit-session-bootstrap"
                        return {"cookie":cookie(reply,"__Host-oidc-session"),"csrf":data(reply)["csrf"]}
                    def logout(browser): return request("POST","/logout",encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])])
                    def begin(mode="query",browser=None,mutation="valid"):
                        if browser is None: browser=bootstrap()
                        if mutation!="valid":control("next/"+mutation)
                        redirect=request("POST","/login/"+mode,encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])])
                        assert redirect[0]==302,"oidc-authorization-redirect"
                        destination=urllib.parse.urlsplit(header(redirect,"location"));issuer=state()["issuer"]
                        assert destination.scheme=="http" and destination.hostname=="127.0.0.1" and destination.geturl().startswith(issuer+"/authorize?"),"fixed-synthetic-provider"
                        parameters=dict(urllib.parse.parse_qsl(destination.query,strict_parsing=True))
                        assert parameters["code_challenge_method"]=="S256" and len(parameters["code_challenge"])==43 and len(parameters["state"])==43 and len(parameters["nonce"])==43,"real-client-state-nonce-pkce"
                        op=http.client.HTTPConnection(destination.hostname,destination.port,timeout=5)
                        try:
                            op.request("GET",destination.path+"?"+destination.query)
                            response=op.getresponse();body=response.read(65537);assert len(body)<=65536,"bounded-op-response"
                            if mode=="query":
                                assert response.status==302,"query-provider-response"
                                fields=dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(response.getheader("Location")).query,strict_parsing=True))
                            else:
                                assert response.status==200,"form-provider-response"
                                class Form(html.parser.HTMLParser):
                                    def __init__(self):super().__init__();self.values={};self.action=None
                                    def handle_starttag(self,tag,attrs):
                                        attrs=dict(attrs)
                                        if tag=="form":self.action=attrs["action"]
                                        elif tag=="input":
                                            assert attrs["name"] not in self.values,"duplicate-fixture-form-input"
                                            self.values[attrs["name"]]=attrs["value"]
                                form=Form();form.feed(body.decode("utf-8"));assert form.action=="https://app.example/oidc/callback","fixed-form-action";fields=form.values
                        finally:op.close()
                        assert fields["state"]==parameters["state"] and fields["iss"]==issuer,"provider-flow-binding"
                        return {**browser,"pending":cookie(redirect,"__Host-oidc-pending"),"fields":fields,"mode":mode,"issuer":issuer}
                    def complete(transaction,changes=None,browser=None,mode=None,extra=(),suffix="",body_suffix=b"",chunked=False):
                        fields=dict(transaction["fields"])
                        if changes:
                            for name,value in changes.items():
                                if value is None:fields.pop(name,None)
                                else:fields[name]=value
                        carrier=transaction if browser is None else browser
                        headers=[("Cookie",carrier["cookie"]+"; "+transaction["pending"]),*extra]
                        selected=mode or transaction["mode"]
                        if selected=="query":return request("GET","/callback?"+urllib.parse.urlencode(fields)+suffix,body_suffix,headers)
                        return request("POST","/callback"+suffix,encoded(fields)+body_suffix,[*media,("Origin",transaction["issuer"]),*headers],chunked=chunked)
                    def authenticated(reply):
                        assert reply[0]==303,"authenticated-fixed-redirect"
                        return {"cookie":cookie(reply,"__Host-oidc-session"),"csrf":data(request("GET","/session",headers=[("Cookie",cookie(reply,"__Host-oidc-session"))]))["csrf"]}
                    def wait_blocked(count=1):
                        deadline=time.monotonic()+1
                        while True:
                            observed=state()
                            if observed["blocked_count"]==count:return
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
                    check("private-fixture-credential",request("GET","/fixture/state",authenticated=False)[0]==401)
                    check("actual-selected-core-and-adapter-origins",state()["origin_verified"] is True)
                    for _ in range(5):check("get-status-does-not-allocate",data(request("GET","/session"))["authenticated"] is False)
                    check("initial-state-empty",state()["sessions"]==0 and state()["attempts"]==0 and state()["state_bytes"]==0)
                    check("bootstrap-requires-exact-origin",request("POST","/session",b"begin=1",media)[0]==403 and state()["sessions"]==0)
                    control("admission-deny");check("admission-before-session-allocation",request("POST","/session",b"begin=1",[*media,*origin])[0]==429 and state()["sessions"]==0);control("admission-allow")
                    for outcome in ["unavailable","unknown"]:
                        browser=bootstrap();before=state();control("pending-save-"+outcome)
                        refused=request("POST","/login/query",encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])])
                        check("pending-save-"+outcome+"-withholds-redirect",refused[0]==503 and not cookies(refused) and not any(name.lower()=="location" for name,value in refused[1]) and state()["attempts"]==before["attempts"] and state()["token_posts"]==before["token_posts"],refused[0])
                        check("pending-save-"+outcome+"-effect-separate",state()["pending_saved"]==before["pending_saved"]+(1 if outcome=="unknown" else 0) and state()["pending_consumed"]==before["pending_consumed"])
                    tx=begin();before=state();control("pending-consume-unknown");refused=complete(tx)
                    check("unknown-pending-removal-withholds-token-work",refused[0]==503 and state()["pending_consumed"]==before["pending_consumed"]+1 and state()["token_posts"]==before["token_posts"] and not any(c.startswith("__Host-oidc-session=") for c in cookies(refused)),refused[0])
                    check("unknown-pending-removal-has-no-retry-or-read-rescue",complete(tx)[0]==401 and state()["token_posts"]==before["token_posts"])
                    positive=[]
                    for mode in ["query","form-post"]:
                        tx=begin(mode);before=state();done=complete(tx)
                        check(mode+"-complete-real-oidc-authentication",done[0]==303,done[0])
                        check("session-rotation-and-pending-deletion-independent",len(cookies(done))==2 and any(c.startswith("__Host-oidc-session=") for c in cookies(done)) and any(c.startswith("__Host-oidc-pending=;") for c in cookies(done)),len(cookies(done)))
                        browser=authenticated(done);positive.append(browser)
                        check("session-id-rotated",browser["cookie"]!=tx["cookie"])
                        check("actual-pkce-and-single-pending-consumption",state()["token_posts"]==before["token_posts"]+1 and state()["pkce_verified"]==before["pkce_verified"]+1 and state()["pending_consumed"]==before["pending_consumed"]+1)
                        check("authenticated-session-cookie-policy","SameSite=Lax" in next(c for c in cookies(done) if c.startswith("__Host-oidc-session=")) and all("Secure" in c and "HttpOnly" in c and "Path=/" in c for c in cookies(done)))
                        check("old-anonymous-session-cannot-authorize",request("GET","/account/tenant/alice",headers=[("Cookie",tx["cookie"])])[0]==401)
                        check("current-account-authorized",request("GET","/account/tenant/alice",headers=[("Cookie",browser["cookie"])])[0]==200)
                        before=state()
                        check("wrong-tenant-refused-before-policy",request("GET","/account/other/alice",headers=[("Cookie",browser["cookie"])])[0]==403 and state()["authorizations"]==before["authorizations"])
                        check("wrong-object-refused-before-policy",request("GET","/account/tenant/bob",headers=[("Cookie",browser["cookie"])])[0]==403 and state()["authorizations"]==before["authorizations"])
                        before=state();check("completed-callback-replay-denied",complete(tx)[0]==401 and state()["token_posts"]==before["token_posts"])
                    control("deny");check("current-account-revocation-enforced",request("GET","/account/tenant/alice",headers=[("Cookie",positive[0]["cookie"])])[0]==403);control("allow")
                    tx=begin(mutation="endpoint-unavailable");before=state();refused=complete(tx)
                    check("token-endpoint-outage-withholds-without-retry",refused[0]==503 and state()["token_posts"]==before["token_posts"]+1 and state()["pkce_verified"]==before["pkce_verified"]+1 and state()["authenticated_sessions"]==before["authenticated_sessions"] and not any(c.startswith("__Host-oidc-session=") for c in cookies(refused)),refused[0])
                    check("consumed-code-outage-cannot-be-replayed",complete(tx)[0]==401 and state()["token_posts"]==before["token_posts"]+1)
                    for mutation in ["wrong-nonce","missing-nonce","wrong-issuer","wrong-audience","wrong-access-hash","wrong-code-hash","expired","signature","old-auth-time","future-auth-time","missing-auth-time","unmapped"]:
                        tx=begin("query",mutation=mutation);before=state();done=complete(tx);after=state()
                        check("signed-token-policy-"+mutation,done[0]==(403 if mutation=="unmapped" else 400) and after["authenticated_sessions"]==before["authenticated_sessions"] and not any(c.startswith("__Host-oidc-session=") for c in cookies(done)),done[0])
                        check("id-token-rejection-before-account-"+mutation,after["lookups"]==before["lookups"]+(1 if mutation=="unmapped" else 0))
                    tx=begin();before=state();control("deny");denied=complete(tx);control("allow")
                    check("current-login-account-policy-required",denied[0]==403 and state()["authenticated_sessions"]==before["authenticated_sessions"],denied[0])
                    for bad in ["wrong-state","missing-issuer","wrong-issuer","wrong-response-mode"]:
                        tx=begin("query");before=state()
                        if bad=="wrong-state":reply=complete(tx,{"state":"wrong"})
                        elif bad=="missing-issuer":reply=complete(tx,{"iss":None})
                        elif bad=="wrong-issuer":reply=complete(tx,{"iss":"https://attacker.invalid"})
                        else:reply=complete(tx,mode="form-post")
                        check("callback-binding-"+bad,reply[0]==400 and state()["token_posts"]==before["token_posts"] and state()["lookups"]==before["lookups"],reply[0])
                    tx=begin("form-post");before=state()
                    check("form-post-cannot-downgrade-to-query",complete(tx,mode="query")[0]==400 and state()["token_posts"]==before["token_posts"])
                    a=begin();b=begin();before=state();mixed=complete(a,browser=b)
                    check("cross-browser-pending-binding-rejected",mixed[0]==401 and state()["pending_consumed"]==before["pending_consumed"] and state()["token_posts"]==before["token_posts"],mixed[0])
                    check("cross-browser-refusal-does-not-consume-victim",complete(a)[0]==303 and complete(b)[0]==303)
                    a=begin();b=begin();before=state();injected=complete(a,{"code":b["fields"]["code"]})
                    check("code-injection-fails-actual-pkce",injected[0]==400 and state()["token_refusals"]==before["token_refusals"]+1 and state()["pkce_verified"]==before["pkce_verified"],injected[0])
                    check("wrong-verifier-does-not-consume-original-code",complete(b)[0]==303)
                    for bad in ["duplicate-query-state","duplicate-form-state","percent-duplicate-state","query-body-split","duplicate-content-type","duplicate-origin","duplicate-session-cookie","malformed-utf8","encoded-path","get-body","header-count"]:
                        mode="query" if bad in ["duplicate-query-state","encoded-path","get-body"] else "form-post"
                        tx=begin(mode);before=state()
                        if bad=="duplicate-query-state":reply=complete(tx,suffix="&state=wrong")
                        elif bad=="duplicate-form-state":reply=complete(tx,body_suffix=b"&state=wrong")
                        elif bad=="percent-duplicate-state":reply=complete(tx,body_suffix=b"&s%74ate=wrong")
                        elif bad=="query-body-split":reply=complete(tx,suffix="?state=wrong")
                        elif bad=="duplicate-content-type":reply=complete(tx,extra=media)
                        elif bad=="duplicate-origin":reply=complete(tx,extra=[("Origin",tx["issuer"])])
                        elif bad=="duplicate-session-cookie":reply=complete(tx,extra=[("Cookie",tx["cookie"])])
                        elif bad=="malformed-utf8":reply=complete(tx,body_suffix=b"&unused=%C3%28")
                        elif bad=="encoded-path":reply=request("GET","/%63allback?"+urllib.parse.urlencode(tx["fields"]),headers=[("Cookie",tx["cookie"]+"; "+tx["pending"])])
                        elif bad=="get-body":reply=complete(tx,body_suffix=b"ignored")
                        else:reply=complete(tx,extra=[("X-Pad-"+str(n),"x") for n in range(33)])
                        after=state();check("raw-carrier-"+bad,400<=reply[0]<500 and after["token_posts"]==before["token_posts"] and after["pending_consumed"]==before["pending_consumed"] and after["attempts"]==before["attempts"],reply[0])
                    tx=begin();before=state();head=request("HEAD","/callback?"+urllib.parse.urlencode(tx["fields"]),headers=[("Cookie",tx["cookie"]+"; "+tx["pending"])])
                    check("unsupported-callback-method-preserves-pending",head[0]==405 and not head[2] and not cookies(head) and state()["pending_consumed"]==before["pending_consumed"] and state()["attempts"]==before["attempts"])
                    check("valid-callback-after-unsupported-method",complete(tx)[0]==303)
                    def padded(transaction):
                        prefix=encoded(transaction["fields"])+b"".join(b"&pad"+str(n).encode()+b"="+b"a"*8180 for n in range(1,4))+b"&pad4="
                        return prefix+b"a"*(32768-len(prefix))
                    tx=begin("form-post");body=padded(tx);assert len(body)==32768
                    large=request("POST","/callback",body,[*media,("Origin",tx["issuer"]),("Cookie",tx["cookie"]+"; "+tx["pending"])],chunked=True)
                    check("callback-body-exact-cap-control",large[0]==303,large[0])
                    tx=begin("form-post");before=state();body=padded(tx)+b"&"
                    large=request("POST","/callback",body,[*media,("Origin",tx["issuer"]),("Cookie",tx["cookie"]+"; "+tx["pending"])],chunked=True)
                    check("callback-chunked-overflow-never-truncated",large[0]==413 and state()["pending_consumed"]==before["pending_consumed"] and state()["attempts"]==before["attempts"],large[0])
                    for lookup in ["late","interrupt","expire"]:
                        tx=begin();before=state();control("lookup-"+lookup);reply=complete(tx)
                        check("late-cancelled-account-work-"+lookup,reply[0]==(401 if lookup=="expire" else 503) and state()["authenticated_sessions"]==before["authenticated_sessions"] and not any(c.startswith("__Host-oidc-session=") for c in cookies(reply)),reply[0])
                        if lookup=="interrupt":check("injected-interrupt-observed-before-fixture-clear",state()["injected_interrupt_observed"] and state()["handler_interrupt_left_set"] and state()["handler_cancel_no_publication"])
                        before=state();check("withheld-callback-not-retried-"+lookup,complete(tx)[0]==401 and state()["token_posts"]==before["token_posts"])
                    for stage in ["token","keys","account"]:
                        if stage=="keys":control("advance-keys")
                        tx=begin();before=state();control("block-"+stage)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                            pending=worker.submit(complete,tx)
                            try:
                                wait_blocked();check("logout-while-"+stage+"-work-is-blocked",logout(tx)[0]==200)
                                check("inflight-retained-state-accounted-"+stage,state()["sessions"]==before["sessions"]-1 and state()["attempts"]==before["attempts"])
                            finally:control("release")
                            refused=pending.result(timeout=5)
                        check("logout-during-"+stage+"-withholds-session",refused[0]==401 and not any(c.startswith("__Host-oidc-session=") for c in cookies(refused)) and state()["authenticated_sessions"]==before["authenticated_sessions"],refused[0])
                    fresh=authenticated(complete(begin()));before=state();control("block-authorize")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                        pending=worker.submit(request,"GET","/account/tenant/alice",b"",[("Cookie",fresh["cookie"])])
                        try:wait_blocked();check("logout-during-authorize-ended-session",logout(fresh)[0]==200)
                        finally:control("release")
                        refused=pending.result(timeout=5)
                    check("logout-during-authorize-withholds-access",refused[0]==401,refused[0])
                    transactions=[begin() for _ in range(9)];before=state();control("block-account")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                        pending=[workers.submit(complete,tx) for tx in transactions[:8]]
                        try:
                            wait_blocked(8);busy=complete(transactions[8]);check("ninth-callback-refused-before-token-work",busy[0]==503 and state()["token_posts"]==before["token_posts"]+8 and not cookies(busy),busy[0])
                        finally:control("release")
                        completed=[future.result(timeout=5) for future in pending]
                    check("admitted-eight-callbacks-publish-once",all(reply[0]==303 for reply in completed) and state()["pending_consumed"]==before["pending_consumed"]+8)
                    check("explicit-later-callback-retains-admission",complete(transactions[8])[0]==303 and state()["token_posts"]==before["token_posts"]+9)
                    fresh=authenticated(complete(begin()));control("block-authorize");before=state()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                        pending=[workers.submit(request,"GET","/account/tenant/alice",b"",[("Cookie",fresh["cookie"])]) for _ in range(8)]
                        try:
                            wait_blocked(8);busy=request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])]);check("protected-account-shares-work-admission",busy[0]==503 and state()["authorizations"]==before["authorizations"]+8,busy[0])
                        finally:control("release")
                        allowed=[future.result(timeout=5) for future in pending]
                    check("protected-account-permits-returned",all(reply[0]==200 for reply in allowed) and request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200)
                    tx=begin();before=state();control("advance-pending");reply=complete(tx)
                    check("pending-expiry-before-token-io",reply[0]==401 and state()["token_posts"]==before["token_posts"] and state()["attempts"]==before["attempts"]-1,reply[0])
                    control("rollback");before=state();check("expired-pending-cannot-revive",complete(tx)[0]==401 and state()["token_posts"]==before["token_posts"])
                    control("recover-clock");fresh=authenticated(complete(begin()));control("advance-session");expired=request("GET","/session",headers=[("Cookie",fresh["cookie"])]);check("session-expiry-ends-authentication",data(expired)["authenticated"] is False)
                    control("rollback");check("observed-expired-session-cannot-revive",data(request("GET","/session",headers=[("Cookie",fresh["cookie"])]))["authenticated"] is False and request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==401)
                    control("recover-clock");fresh=authenticated(complete(begin()))
                    for _ in range(129):
                        if state()["sessions"]>=128:break
                        bootstrap()
                    before=state();full=request("POST","/session",b"begin=1",[*media,*origin])
                    check("session-capacity-refuses-without-live-eviction",before["sessions"]==128 and full[0]==503 and not cookies(full) and state()["sessions"]==128 and request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200,full[0])
                    control("advance-session");recovered=bootstrap();check("expiry-cleanup-is-bounded-and-accounted",state()["sessions"]==113 and state()["state_bytes"]<=65536,state())
                    control("rollback");check("rollback-refuses-future-created-session",data(request("GET","/session",headers=[("Cookie",recovered["cookie"])]))["authenticated"] is False)
                    control("recover-clock");tx=begin();control("outage");before=state();refused=complete(tx)
                    check("key-source-outage-withholds-without-retry",refused[0]==503 and state()["key_requests"]==before["key_requests"]+1 and state()["lookups"]==before["lookups"] and state()["authenticated_sessions"]==before["authenticated_sessions"] and not any(c.startswith("__Host-oidc-session=") for c in cookies(refused)),refused[0])
                    check("key-source-failure-pending-cannot-be-replayed",complete(tx)[0]==401 and state()["token_posts"]==before["token_posts"]+1 and state()["key_requests"]==before["key_requests"]+1)
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
