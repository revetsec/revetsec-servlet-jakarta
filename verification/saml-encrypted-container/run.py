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

"""Qualify encrypted assertions through the actual paired S3 application in owned pinned Tomcat."""
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
    parser.add_argument("--encryption-key", type=Path)
    parser.add_argument("--encryption-certificate", type=Path)
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
    sources = [recipe, repo/"verification/saml-sp-container/SamlSpServlet.java", fixture/"SamlSpFixture.java"]
    key_root=repo.parent/"revetsec/src/test/resources/fixtures/keys"
    key=args.encryption_key or key_root/"sp-encryption-rsa-2048-key.pem"
    certificate=args.encryption_certificate or key_root/"sp-encryption-rsa-2048-cert.pem"
    auditor = repo/"verification/nullability/NullabilityAudit.java"
    for item in [args.tomcat_archive, args.core_jar, args.adapter_jar, *annotations, *sources, auditor, pins_path, key, certificate]:
        if not item.is_file(): parser.error("Required input missing: "+str(item))
    if not re.fullmatch("[0-9a-f]{64}", args.core_sha256) or digest(args.core_jar) != args.core_sha256:
        parser.error("Selected core SHA256 mismatch before instance creation")
    if not re.fullmatch("[0-9a-f]{64}", args.adapter_sha256) or digest(args.adapter_jar) != args.adapter_sha256:
        parser.error("Selected adapter SHA256 mismatch before instance creation")
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive differs from reviewed SHA512")
    if args.output.exists(): parser.error("Use a fresh evidence output directory")
    inputs = {str(p.resolve()): digest(p) for p in [*sources, auditor, pins_path, key, certificate, Path(__file__)]}
    receipt = {"namespace": namespace, "runtime": pins["version"], "runtimeSha512": pins["archiveSha512"],
               "coreJarSha256": args.core_sha256, "adapterJarSha256": args.adapter_sha256, "sourceInputs": inputs, "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Synthetic signed/encrypted XML with independent JCA unwrap/decrypt/signature oracle, configured real core decryption and actual S3 account/session controls; pinned Servlet runtime. Fixed clock/keys and plaintext loopback secure transport declaration; no real browser/TLS/hosted IdP, distributed store, full encryption matrix, formal S3 tools or final merged release claim"}
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
                copied_key=instance/"encryption-key.pem";copied_certificate=instance/"encryption-cert.pem"
                shutil.copyfile(key,copied_key);copied_key.chmod(0o600);shutil.copyfile(certificate,copied_certificate)
                if digest(copied_key)!=digest(key) or digest(copied_certificate)!=digest(certificate):raise RuntimeError("Selected encryption fixture changed during copy")
                credential = secrets.token_urlsafe(32)
                environment = dict(os.environ)
                environment.pop("JAVA_TOOL_OPTIONS", None); environment.pop("JDK_JAVA_OPTIONS", None)
                environment["REVETSEC_SAML_ENCRYPTION_KEY"] = str(copied_key)
                environment["REVETSEC_SAML_ENCRYPTION_CERTIFICATE"] = str(copied_certificate)
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
                    for connection in ["idp-a","idp-b"]:
                        for mode in ["redirect","post"]:
                            before=state();tx=begin(connection=connection,mode=mode);reply=complete(tx)
                            check("encrypted-login-publishes-"+connection+'-'+mode,reply[0]==303,reply[0]);fresh=authenticated(reply);after=state()
                            check("jca-encryption-and-both-signatures-"+connection+'-'+mode,all(after[k]==before[k]+1 for k in ["encrypted_minted","jca_roundtrips","jca_inner_verified","jca_outer_verified"]))
                            check("encrypted-pending-consumed-and-account-checked-"+connection+'-'+mode,after["consumed"]==before["consumed"]+1 and after["lookups"]==before["lookups"]+1 and after["authorizations"]==before["authorizations"]+1)
                            check("encrypted-session-rotation-and-separate-cookies-"+connection+'-'+mode,fresh["cookie"]!=tx["cookie"] and len(cookies(reply))==2 and data(request("GET","/session",headers=[("Cookie",tx["cookie"])]))["authenticated"] is False)
                            check("encrypted-current-tenant-owner-"+connection+'-'+mode,request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200 and request("GET","/account/other/alice",headers=[("Cookie",fresh["cookie"])])[0]==403 and request("GET","/account/tenant/bob",headers=[("Cookie",fresh["cookie"])])[0]==403)
                            check("encrypted-callback-one-use-"+connection+'-'+mode,complete(tx)[0]==401)
                            check("encrypted-local-logout-"+connection+'-'+mode,logout(fresh)[0]==200 and request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==401)
                    before=state();tx=begin(mutation="missing-outer-signature");fresh=authenticated(complete(tx));after=state()
                    check("encrypted-signed-assertion-without-outer-signature",after["jca_inner_verified"]==before["jca_inner_verified"]+1 and after["jca_outer_verified"]==before["jca_outer_verified"] and request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200);logout(fresh)
                    crypto_modes=["wrong-recipient-key","bad-tag","bad-ciphertext","unsupported-data-algorithm","unsupported-key-algorithm","inner-wrong-key","inner-tamper","outer-wrong-key","outer-tamper","missing-inner-signature"]
                    for mode in crypto_modes+["wrong-issuer","wrong-audience","wrong-destination","wrong-request","wrong-recipient","expired","unmapped"]:
                        before=state();tx=begin(mode="post",mutation=mode);minted=state();reply=complete(tx);after=state()
                        check("encrypted-refuses-"+mode,reply[0] in [400,403,503] and no_publication(reply) and after["authenticated_sessions"]==before["authenticated_sessions"],reply[0])
                        if mode!="unmapped":check("encrypted-refusal-before-account-"+mode,after["lookups"]==before["lookups"])
                        if mode not in ["outer-wrong-key","outer-tamper","missing-outer-signature"]:check("hostile-encryption-keeps-valid-outer-signature-"+mode,minted["jca_outer_verified"]==before["jca_outer_verified"]+1)
                        check("encrypted-rejected-attempt-not-retried-"+mode,complete(tx)[0]==401)
                    tx=begin();before=state()
                    check("raw-duplicate-ciphertext-field-before-consume",complete(tx,body=tx["mint"]["body"].encode()+b'&SAMLResponse=x')[0]==400 and state()["consumed"]==before["consumed"])
                    check("encrypted-query-form-confusion",request("POST","/acs?RelayState=other",tx["mint"]["body"].encode(),[*media,("Cookie",tx["cookie"]+'; '+tx["pending"]),("Origin","https://idpa.example.test")])[0]==400 and state()["consumed"]==before["consumed"])
                    check("encrypted-body-plus-one-before-consume",complete(tx,body=b'x'*65537)[0]==413 and state()["consumed"]==before["consumed"])
                    check("encrypted-chunked-body-plus-one-before-consume",request("POST","/acs",b'x'*65537,[*media,("Cookie",tx["cookie"]+'; '+tx["pending"]),("Origin","https://idpa.example.test")],chunked=True)[0]==413 and state()["consumed"]==before["consumed"])
                    changed=dict(tx);changed["connection"]="idp-b"
                    check("encrypted-saved-provider-binding",complete(changed)[0]==403 and state()["consumed"]==before["consumed"])
                    fresh=authenticated(complete(tx,origin_override="null"));check("encrypted-null-origin-needs-genuine-bound-proof",request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==200);logout(fresh)
                    tx=begin();before=state();control("deny");reply=complete(tx)
                    check("encrypted-current-account-policy",reply[0]==403 and no_publication(reply) and state()["authenticated_sessions"]==before["authenticated_sessions"]);control("allow")
                    fresh=authenticated(complete(begin()));control("generation")
                    check("encrypted-current-account-generation",request("GET","/account/tenant/alice",headers=[("Cookie",fresh["cookie"])])[0]==403);logout(fresh)
                    tx=begin();before=state();control("lookup-expire");reply=complete(tx)
                    check("encrypted-exact-assertion-expiry-after-account",reply[0]==401 and no_publication(reply) and state()["authenticated_sessions"]==before["authenticated_sessions"],reply[0]);control("recover-clock")
                    tx=begin();before=state();control("block-account")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                        pending=pool.submit(complete,tx)
                        try:wait_blocked();check("encrypted-logout-during-account-local-first",logout(tx)[0]==200)
                        finally:control("release")
                        reply=pending.result(timeout=6)
                    check("encrypted-cancelled-account-does-not-publish",reply[0]==401 and no_publication(reply) and state()["authenticated_sessions"]==before["authenticated_sessions"],reply[0])
                    fresh=authenticated(complete(begin()));control("block-authorize")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                        pending=pool.submit(request,"GET","/account/tenant/alice",b'',[("Cookie",fresh["cookie"])])
                        try:wait_blocked();logout(fresh)
                        finally:control("release")
                        reply=pending.result(timeout=6)
                    check("encrypted-cancelled-authorization-withholds-data",reply[0]==401)
                    receipt["finalState"]=state();assert all(digest(Path(path))==value for path,value in inputs.items()),"Qualification source changed during run";receipt["sourceStable"]=True;receipt["success"]=True
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
