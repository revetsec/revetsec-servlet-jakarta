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

"""Qualify the complete paired single-process S3 SAML SP host in owned pinned Tomcat."""
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
    recipe = args.recipe_source or repo/"docs/ServletSamlSpRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    sources = [recipe, fixture/"SamlSpServlet.java", fixture/"SamlSpFixture.java"]
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
               "scope": "Synthetic signed-XML IdPs/current account collaborators; real Servlet container; no real browser/TLS/hosted IdP, distributed store or formal S3 tool pass claim"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-saml-sp-"+namespace+"-") as directory:
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
                    '<web-app><servlet><servlet-name>saml</servlet-name><servlet-class>example.SamlSpServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>saml</servlet-name>'
                    '<url-pattern>/saml/*</url-pattern></servlet-mapping></web-app>')
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
                environment["REVETSEC_SAML_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_SAML_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_SAML_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_SAML_ADAPTER_JAR"] = str(copied_adapter)
                environment["REVETSEC_SAML_ADAPTER_SHA256"] = args.adapter_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, "/saml"+path, skip_host=True, skip_accept_encoding=True)
                            connection.putheader("Host", "sp.example.test")
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
                        assert 0<=value["state_bytes"]<=262144,"bounded-state-charge"
                        return value
                    def control(command): return request("GET","/fixture/"+command)
                    def encoded(fields): return urllib.parse.urlencode(fields).encode("ascii")
                    media=[("Content-Type","application/x-www-form-urlencoded")]
                    origin=[("Origin","https://sp.example.test")]
                    def bootstrap():
                        reply=request("POST","/session",b"begin=1",[*media,*origin]);assert reply[0]==200,"explicit-session-bootstrap"
                        return {"cookie":cookie(reply,"__Host-saml-session"),"csrf":data(reply)["csrf"]}
                    def logout(browser,mode="local"):
                        return request("POST","/logout/"+mode,encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])])
                    class Forms(html.parser.HTMLParser):
                        def __init__(self):super().__init__();self.action=None;self.fields={}
                        def handle_starttag(self,tag,attrs):
                            fields=dict(attrs)
                            if tag=="form":self.action=fields.get("action")
                            if tag=="input" and "name" in fields:self.fields[fields["name"]]=fields.get("value","")
                    def outbound(reply,mode):
                        if mode=="redirect":
                            assert reply[0]==303,"signed-authn-redirect"
                            dest=urllib.parse.urlsplit(header(reply,"location"));return dest.geturl(),dest.query,"GET"
                        assert reply[0]==200,"signed-authn-post"
                        parsed=Forms();parsed.feed(reply[2].decode());assert parsed.action and "SAMLRequest" in parsed.fields,"actual-signed-post-fields"
                        return parsed.action,urllib.parse.urlencode(parsed.fields),"POST"
                    def begin(connection="idp-a",mode="redirect",mutation="valid",browser=None):
                        browser=browser or bootstrap()
                        reply=request("POST","/login/"+connection+'/'+mode,encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])])
                        destination,raw,method=outbound(reply,mode)
                        assert urllib.parse.urlsplit(destination).hostname==("idpa.example.test" if connection=="idp-a" else "idpb.example.test"),"fixed-trusted-idp-endpoint"
                        minted=request("POST","/fixture/mint/"+connection+'/'+mutation+'/'+method,raw.encode(),media)
                        assert minted[0]==200,"signed-idp-fixture-mint"
                        return {**browser,"pending":cookie(reply,"__Host-saml-pending"),"mint":data(minted),"connection":connection,"raw":raw,"delivery":method,"reply":reply}
                    def complete(tx,body=None,extra=(),cookies_override=None,origin_override=None):
                        return request("POST","/acs",(body if body is not None else tx["mint"]["body"].encode()),[*media,("Origin",origin_override or "https://"+("idpa" if tx["connection"]=="idp-a" else "idpb")+".example.test"),("Cookie",cookies_override or tx["cookie"]+'; '+tx["pending"]),*extra])
                    def authenticated(reply):
                        assert reply[0]==303,"saml-session-published"
                        session_cookie=cookie(reply,"__Host-saml-session");value=data(request("GET","/session",headers=[("Cookie",session_cookie)]));assert value["authenticated"] is True,"saml-session-current"
                        return {"cookie":session_cookie,"csrf":value["csrf"]}
                    def no_publication(reply):return not any(item.startswith("__Host-saml-session=") for item in cookies(reply)) and not any(k.lower()=="location" for k,v in reply[1])
                    def wait_blocked(count=1):
                        deadline=time.monotonic()+3
                        while time.monotonic()<deadline:
                            value=state();receipt["lastBlockedState"]=value
                            if value["blocked_count"]>=count:return
                            time.sleep(.015)
                        raise AssertionError("collaborator-reached-latch")
                    deadline=time.monotonic()+12
                    while True:
                        try:
                            if request("GET","/fixture/state")[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>deadline:raise RuntimeError("Pinned Tomcat startup failed")
                        time.sleep(.05)
                    check("actual-selected-artifact-origins",state()["origin_verified"])
                    check("get-does-not-allocate",data(request("GET","/session"))["authenticated"] is False and state()["sessions"]==0)
                    check("fixture-controls-require-credential",request("GET","/fixture/state",authenticated=False)[0]==401)
                    check("cross-origin-bootstrap-denied",request("POST","/session",b"begin=1",[*media,("Origin","https://wrong.invalid")])[0]==403)
                    check("bootstrap-body-bound",request("POST","/session",b"a"*129,[*media,*origin])[0]==413 and state()["sessions"]==0)
                    check("chunked-bootstrap-body-bound",request("POST","/session",b"a"*129,[*media,*origin],chunked=True)[0]==413 and state()["sessions"]==0)
                    browser=bootstrap();before=state()
                    check("bootstrap-independent-cookie-flags",all(x in browser["cookie"] for x in ["__Host-saml-session="]) and any("SameSite=None" in c and "Secure" in c and "HttpOnly" in c for c in cookies(request("POST","/session",b"begin=1",[*media,*origin,("Cookie",browser["cookie"])]))))
                    check("login-csrf-denied-before-core",request("POST","/login/idp-a/redirect",b"csrf=wrong",[*media,*origin,("Cookie",browser["cookie"])])[0]==403 and state()["saved"]==before["saved"])
                    for mode in ["redirect","post"]:
                        tx=begin(mode=mode);before=state();reply=complete(tx);fresh=authenticated(reply)
                        check("solicited-"+mode+"-login-rotates-session",fresh["cookie"]!=tx["cookie"] and data(request("GET","/session",headers=[("Cookie",tx["cookie"])]))["authenticated"] is False)
                        check("independent-session-and-pending-set-cookie-"+mode,len(cookies(reply))==2 and any("SameSite=Lax" in c for c in cookies(reply)) and any("__Host-saml-pending=;" in c for c in cookies(reply)))
                        check("actual-pending-consumed-before-account-"+mode,state()["consumed"]==before["consumed"]+1 and state()["lookups"]==before["lookups"]+1)
                        check("one-use-callback-"+mode,complete(tx)[0]==401)
                        check("current-tenant-owner-"+mode,request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200 and request("GET","/account/other/alice",headers=[("Cookie",fresh["cookie"])])[0]==403 and request("GET","/account/tenant/bob",headers=[("Cookie",fresh["cookie"])])[0]==403)
                        logout(fresh)
                    for mutation in ["wrong-key","wrong-issuer","wrong-audience","wrong-destination","wrong-request","wrong-recipient","expired","future-authn","prior-request-authn","old-authn","unmapped","duplicate-assertion","duplicate-id","doctype","encrypted-bad","tamper-subject","xsw-outside-assertion","xsw-unsigned-assertion","xslt-transform","external-reference"]:
                        tx=begin(mode="post",mutation=mutation);before=state();reply=complete(tx)
                        check("signed-xml-mutation-"+mutation,reply[0] in [400,401,403,503] and no_publication(reply) and state()["authenticated_sessions"]==before["authenticated_sessions"],reply[0])
                        check("mutation-pending-not-retried-"+mutation,complete(tx)[0]==401 and state()["consumed"]==before["consumed"]+1)
                    tx=begin(mutation="comment-split");fresh=authenticated(complete(tx));check("canonical-equivalent-comment-preserves-logical-subject",request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200);logout(fresh)
                    tx=begin();before=state();reply=complete(tx,cookies_override=tx["cookie"],origin_override="null")
                    check("null-origin-without-browser-pending-denied",reply[0]==401 and state()["consumed"]==before["consumed"] and no_publication(reply))
                    fresh=authenticated(complete(tx,origin_override="null"));check("null-origin-is-auxiliary-to-signed-bound-proof",request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200);logout(fresh)
                    tx=begin(mutation="wrong-key");before=state();reply=complete(tx,origin_override="null")
                    check("null-origin-wrong-signature-no-account-proof",reply[0] in [400,503] and state()["lookups"]==before["lookups"] and no_publication(reply))
                    tx=begin();before=state();other=bootstrap();reply=complete(tx,cookies_override=other["cookie"]+'; '+tx["pending"])
                    check("wrong-current-session-before-consume",reply[0]==401 and state()["consumed"]==before["consumed"] and no_publication(reply))
                    fresh=authenticated(complete(tx));logout(fresh)
                    tx=begin();before=state();bad=tx["mint"]["body"].encode()+b'&RelayState=other'
                    check("raw-duplicate-field-before-consume",complete(tx,body=bad)[0]==400 and state()["consumed"]==before["consumed"])
                    check("raw-query-form-confusion",request("POST","/acs?RelayState=other",tx["mint"]["body"].encode(),[*media,("Cookie",tx["cookie"]+'; '+tx["pending"]),("Origin","https://idpa.example.test")])[0]==400 and state()["consumed"]==before["consumed"])
                    check("duplicate-media-before-consume",complete(tx,extra=media)[0]==400 and state()["consumed"]==before["consumed"])
                    check("encoded-duplicate-field-alias-before-consume",complete(tx,body=tx["mint"]["body"].encode()+b'&%53AMLResponse=x')[0]==400 and state()["consumed"]==before["consumed"])
                    check("duplicate-cookie-before-consume",complete(tx,cookies_override=tx["cookie"]+'; '+tx["pending"]+'; '+tx["pending"])[0]==400 and state()["consumed"]==before["consumed"])
                    check("body-plus-one-before-consume",complete(tx,body=b'x'*65537)[0]==413 and state()["consumed"]==before["consumed"])
                    check("chunked-body-plus-one-before-consume",request("POST","/acs",b'x'*65537,[*media,("Cookie",tx["cookie"]+'; '+tx["pending"]),("Origin","https://idpa.example.test")],chunked=True)[0]==413 and state()["consumed"]==before["consumed"])
                    changed=dict(tx);changed["connection"]="idp-b"
                    check("saved-provider-origin-authoritative",complete(changed)[0]==403 and state()["consumed"]==before["consumed"])
                    cross=data(request("POST","/fixture/mint/idp-b/valid/"+tx["delivery"],tx["raw"].encode(),media));changed=dict(tx);changed["mint"]=cross
                    reply=complete(changed);check("other-idp-key-and-issuer-denied",reply[0] in [400,503] and no_publication(reply) and state()["lookups"]==before["lookups"])
                    for fault in ["save-unavailable","save-unknown"]:
                        browser=bootstrap();control(fault);before=state();reply=request("POST","/login/idp-a/post",encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])])
                        check("pending-"+fault+"-no-delivery",reply[0]==503 and no_publication(reply) and state()["attempts"]==before["attempts"])
                    tx=begin();control("consume-unknown");before=state();reply=complete(tx);check("pending-consume-unknown-no-proof",reply[0]==503 and no_publication(reply) and state()["lookups"]==before["lookups"] and complete(tx)[0]==401)
                    for fault in ["lookup-expire","lookup-late","lookup-interrupt"]:
                        tx=begin();before=state();control(fault);reply=complete(tx)
                        check(fault+"-no-session",reply[0] in [401,503] and no_publication(reply) and state()["authenticated_sessions"]==before["authenticated_sessions"],reply[0]);control("recover-clock")
                    check("cancel-retains-interrupt-and-no-publication",state()["interrupt_observed"] and state()["handler_interrupt_left_set"] and state()["handler_cancel_no_publication"])
                    tx=begin();before=state();control("block-account")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending=pool.submit(complete,tx)
                        try:wait_blocked();check("logout-during-account-local-first",logout(tx)[0]==200)
                        finally:control("release")
                        reply=pending.result(timeout=6)
                    check("logout-during-account-withholds-session",reply[0]==401 and no_publication(reply))
                    fresh=authenticated(complete(begin()));control("block-authorize")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending=pool.submit(request,"GET","/account/tenant/alice",b'',[("Cookie",fresh["cookie"])])
                        try:wait_blocked();logout(fresh)
                        finally:control("release")
                        reply=pending.result(timeout=6)
                    check("logout-during-authorize-withholds-data",reply[0]==401)
                    fresh=authenticated(complete(begin()));control("generation")
                    check("current-account-generation-denied",request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==403);logout(fresh)
                    for mode in ["redirect","post"]:
                        fresh=authenticated(complete(begin()));started=logout(fresh,mode);destination,raw,method=outbound(started,mode)
                        check("local-session-ended-before-provider-"+mode,request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==401 and any(c.startswith('__Host-saml-session=;') for c in cookies(started)))
                        minted=data(request("POST","/fixture/mint/idp-a/valid/"+method,raw.encode(),media));pending_cookie=cookie(started,"__Host-saml-logout")
                        path='/logout-return/'+mode
                        bad=data(request("POST","/fixture/mint/idp-a/wrong-key/"+method,raw.encode(),media))
                        rejected=request('POST',path,bad['body'].encode(),[*media,("Origin","null"),("Cookie",pending_cookie)]) if mode=='post' else request('GET',path+'?'+bad['body'],headers=[('Cookie',pending_cookie)])
                        check("forged-provider-return-preserves-valid-pending-"+mode,rejected[0]==400 and not cookies(rejected))
                        reply=request('POST',path,minted['body'].encode(),[*media,("Origin","https://idpa.example.test"),("Cookie",pending_cookie)]) if mode=='post' else request('GET',path+'?'+minted['body'],headers=[('Cookie',pending_cookie)])
                        check("correlated-single-use-provider-logout-"+mode,reply[0]==200 and data(reply)["provider_logout_reported"] and len(cookies(reply))==1 and not any(c.startswith('__Host-saml-session=') for c in cookies(reply)))
                        replay=request('POST',path,minted['body'].encode(),[*media,("Origin","https://idpa.example.test"),("Cookie",pending_cookie)]) if mode=='post' else request('GET',path+'?'+minted['body'],headers=[('Cookie',pending_cookie)])
                        check("provider-logout-replay-"+mode,replay[0]==401)
                    fresh=authenticated(complete(begin()));control('save-unavailable');reply=logout(fresh,'post')
                    check("logout-save-refusal-keeps-local-ended",reply[0]==503 and any(c.startswith('__Host-saml-session=;') for c in cookies(reply)) and request('GET','/account/tenant/alice',headers=[('Cookie',fresh['cookie'])])[0]==401)
                    for method in ['POST','GET']:
                        fresh=authenticated(complete(begin()))
                        for mutation in ['wrong-name','wrong-format','wrong-qualifier','wrong-sp-qualifier','wrong-sp-provided','wrong-index','wrong-key']:
                            minted=data(request('POST','/fixture/idp-logout/idp-a/'+mutation+'/'+method,b'x',media));path='/idp-logout/idp-a/'+('post' if method=='POST' else 'redirect')
                            reply=request('POST',path,minted['body'].encode(),[*media,('Origin','https://idpa.example.test')]) if method=='POST' else request('GET',path+'?'+minted['body'])
                            check('idp-logout-full-reference-'+method+'-'+mutation,request('GET','/account/tenant/alice',headers=[('Cookie',fresh['cookie'])])[0]==200)
                        minted=data(request('POST','/fixture/idp-logout/idp-a/valid/'+method,b'x',media));path='/idp-logout/idp-a/'+('post' if method=='POST' else 'redirect')
                        reply=request('POST',path,minted['body'].encode(),[*media,('Origin','https://idpa.example.test')]) if method=='POST' else request('GET',path+'?'+minted['body'])
                        check('signed-idp-logout-matching-session-'+method,reply[0] in [200,303] and request('GET','/account/tenant/alice',headers=[('Cookie',fresh['cookie'])])[0]==401,reply[0])
                    # Fresh replay windows before contention and exact quota exhaustion.
                    control('advance-session');control('recover-clock')
                    transactions=[begin() for _ in range(9)];before=state();control('block-account')
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                        pending=[workers.submit(complete,tx) for tx in transactions[:8]]
                        try:wait_blocked(8);busy=complete(transactions[8]);check('ninth-callback-before-pending-consume',busy[0]==503 and state()['consumed']==before['consumed']+8 and no_publication(busy))
                        finally:control('release')
                        completed=[future.result(timeout=6) for future in pending]
                    check('eight-callbacks-publish-once',all(reply[0]==303 for reply in completed))
                    check('explicit-later-admitted-callback',complete(transactions[8])[0]==303)
                    # Release old anonymous fixture sessions through bounded real expiry cleanup.
                    control('advance-session');control('recover-clock')
                    tx=begin();before=state();control('advance-pending');reply=complete(tx)
                    check('observed-expired-pending-discarded',reply[0]==401 and state()['consumed']==before['consumed'] and state()['attempts']==before['attempts']-1)
                    control('rollback');check('observed-expired-pending-cannot-revive',complete(tx)[0]==401);control('recover-clock')
                    fresh=authenticated(complete(begin(connection='idp-b')));control('advance-session')
                    check('session-expiry-ends-authentication',data(request('GET','/session',headers=[('Cookie',fresh['cookie'])]))['authenticated'] is False)
                    control('rollback');check('observed-expired-session-cannot-revive',data(request('GET','/session',headers=[('Cookie',fresh['cookie'])]))['authenticated'] is False);control('recover-clock')
                    retained=[begin() for _ in range(32)];other=bootstrap();before=state()
                    refused=request('POST','/login/idp-a/redirect',encoded({'csrf':other['csrf']}),[*media,*origin,('Cookie',other['cookie'])])
                    check('idp-a-pending-reservation-refuses-without-eviction',refused[0]==503 and no_publication(refused) and state()['attempts']==before['attempts'])
                    fresh=authenticated(complete(begin(connection='idp-b')))
                    check('idp-a-pending-cap-leaves-idp-b-admission',request('GET','/account/tenant/alice',headers=[('Cookie',fresh['cookie'])])[0]==200)
                    for _ in range(129):
                        if state()['sessions']>=128:break
                        bootstrap()
                    before=state();refused=request('POST','/session',b'begin=1',media+origin)
                    check('session-cap-refuses-no-live-eviction',before['sessions']==128 and refused[0]==503 and not cookies(refused) and state()['sessions']==128 and request('GET','/account/tenant/alice',headers=[('Cookie',fresh['cookie'])])[0]==200)
                    control('advance-session');bootstrap();value=state()
                    check('expiry-cleanup-bounded-session-scan',value['sessions']==113 and value['attempts']<=16,value)
                    for _ in range(7):bootstrap()
                    value=state();check('expired-string-byte-charge-fully-released',value['sessions']==8 and value['attempts']==0 and value['state_bytes']==86*8,value)
                    a_success=0;refusal=None;start_marks_a=state()["marks_a"]
                    for _ in range(70):
                        tx=begin();reply=complete(tx)
                        if reply[0]==303:a_success+=1;logout(authenticated(reply))
                        else:refusal=reply;break
                    check('idp-a-reserved-replay-quota-refuses-without-proof',refusal is not None and refusal[0]==503 and no_publication(refusal) and state()['marks_a']-start_marks_a==64,a_success)
                    before=state();fresh=authenticated(complete(begin(connection='idp-b',mode='post')))
                    check('idp-a-exhaustion-leaves-idp-b-reservation',state()['marks_b']>before['marks_b'] and request('GET','/account/tenant/alice',headers=[('Cookie',fresh['cookie'])])[0]==200)
                    logout(fresh);receipt['finalState']=state();assert all(digest(Path(path))==value for path,value in inputs.items()),'Qualification source changed during run';receipt['success']=True
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
