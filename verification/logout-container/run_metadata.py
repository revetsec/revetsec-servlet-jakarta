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

"""Qualify the complete paired single-process local-first OIDC RP logout host in owned pinned Tomcat."""
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
    parser.add_argument("--common-jar", type=Path, required=True)
    parser.add_argument("--common-sha256", required=True)
    parser.add_argument("--fixture-jar",type=Path,required=True)
    parser.add_argument("--fixture-sha256",required=True)
    parser.add_argument("--delivery",choices=["form","get"],default="form")
    parser.add_argument("--padding",choices=[0,6000],type=int,default=0)
    parser.add_argument("--fixture-supplement",action="store_true",help="Run qualified fixture checked-interruption and bounded native contention controls")
    parser.add_argument("--metadata-fault",choices=["outage","unsupported"],default="outage")
    parser.add_argument("--recipe-source", type=Path, help="Private carrier calibration override; recorded by exact digest")
    parser.add_argument("--annotations-repository", type=Path, default=Path.home()/".m2/repository")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    recipe = args.recipe_source or repo/"docs/ServletOidcLogoutRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    sources = [recipe, fixture/"OidcLogoutServlet.java", fixture/"CarrierContractChecks.java"]
    auditor = repo/"verification/nullability/NullabilityAudit.java"
    for item in [args.tomcat_archive, args.core_jar, args.common_jar, args.fixture_jar, *annotations, *sources, auditor, pins_path]:
        if not item.is_file(): parser.error("Required input missing: "+str(item))
    if not re.fullmatch("[0-9a-f]{64}", args.core_sha256) or digest(args.core_jar) != args.core_sha256:
        parser.error("Selected core SHA256 mismatch before instance creation")
    if not re.fullmatch("[0-9a-f]{64}", args.common_sha256) or digest(args.common_jar) != args.common_sha256:
        parser.error("Selected common SHA256 mismatch before instance creation")
    if not re.fullmatch("[0-9a-f]{64}",args.fixture_sha256) or digest(args.fixture_jar)!=args.fixture_sha256:
        parser.error("Selected fixture SHA256 mismatch before instance creation")
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive differs from reviewed SHA512")
    if args.output.exists(): parser.error("Use a fresh evidence output directory")
    inputs = {str(p.resolve()): digest(p) for p in [*sources, auditor, pins_path, Path(__file__)]}
    receipt = {"namespace": namespace, "runtime": pins["version"], "runtimeSha512": pins["archiveSha512"],
               "coreJarSha256": args.core_sha256, "commonJarSha256": args.common_sha256,"fixtureJarSha256":args.fixture_sha256,"delivery":args.delivery,"padding":args.padding,"fixtureSupplement":args.fixture_supplement, "sourceInputs": inputs, "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Synthetic real OP/PKCE/signature fixture; actual Servlet container; HTTP secureflag is not real TLS/browser/provider or durable/final-merge qualification"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-logout-"+namespace+"-") as directory:
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
                copied_common=base/"webapps/ROOT/WEB-INF/lib/common.jar"
                shutil.copyfile(args.common_jar,copied_common)
                if digest(copied_common)!=args.common_sha256:raise RuntimeError("Selected common changed during copy")
                copied_fixture=base/"webapps/ROOT/WEB-INF/lib/fixture.jar"
                shutil.copyfile(args.fixture_jar,copied_fixture)
                if digest(copied_fixture)!=args.fixture_sha256:raise RuntimeError("Selected fixture changed during copy")
                classpath = os.pathsep.join(map(str, [args.core_jar, args.common_jar,args.fixture_jar, home/"lib/servlet-api.jar", *annotations]))
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
                contract=subprocess.run([str(args.java_home/"bin/java"),"-cp",os.pathsep.join(map(str,[classes,args.core_jar,args.common_jar,args.fixture_jar,home/"lib/servlet-api.jar"])),"example.CarrierContractChecks"],capture_output=True,text=True,timeout=15)
                (args.output/"carrier-contract.log").write_text(contract.stdout+contract.stderr)
                if contract.returncode:raise RuntimeError("Focused carrier output/startup contract failed")
                receipt["checks"].append({"name":"output-failure-and-startup-assurance-contract","passed":True})
                (base/"webapps/ROOT/WEB-INF/web.xml").write_text(
                    '<web-app><servlet><servlet-name>logout</servlet-name><servlet-class>example.OidcLogoutServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>logout</servlet-name>'
                    '<url-pattern>/logout/*</url-pattern></servlet-mapping><servlet-mapping><servlet-name>logout</servlet-name><url-pattern>/fixture/*</url-pattern></servlet-mapping></web-app>')
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
                environment["REVETSEC_LOGOUT_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_LOGOUT_FIXTURE_JAR"]=str(copied_fixture)
                environment["REVETSEC_LOGOUT_FIXTURE_SHA256"]=args.fixture_sha256
                environment["REVETSEC_LOGOUT_DELIVERY"]=args.delivery
                environment["REVETSEC_LOGOUT_PADDING"]=str(args.padding)
                environment["REVETSEC_LOGOUT_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_LOGOUT_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_LOGOUT_COMMON_JAR"] = str(copied_common)
                environment["REVETSEC_LOGOUT_COMMON_SHA256"] = args.common_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, path if path.startswith("/fixture/") else "/logout"+path, skip_host=True, skip_accept_encoding=True)
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
                            payload = response.read(131073)
                            assert len(payload) <= 131072, "bounded-response"
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
                        value=data(request('GET','/fixture/control/state'));value.update(value.pop('shared'));return value
                    def control(command):return request('GET','/fixture/control/'+command)
                    deadline=time.monotonic()+12
                    while True:
                        try:
                            if request('GET','/fixture/control/state')[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>deadline:raise RuntimeError('Pinned Tomcat startup failed')
                        time.sleep(.05)
                    check('fresh-process-no-prior-discovery',state()['discovery']==0 and state()['closes']==0 and state()['saves']==0)
                    bootstrap=request('POST','/fixture/login',b'begin=1',[("Content-Type","application/x-www-form-urlencoded")])
                    check('genuine-flow-before-fresh-metadata-fault',bootstrap[0]==200 and data(bootstrap)['genuine_authentication'] is True)
                    sid=cookie(bootstrap,'__Host-app-session');csrf=data(bootstrap)['csrf'];before=state();receipt['beforeFault']=before
                    check('only-one-genuine-bootstrap-discovery',before['discovery']==1 and before['token_posts']==1 and before['sessions']==1)
                    fault=control('metadata/'+args.metadata_fault);check('explicit-fault-armed-after-cache-expiry',fault[0]==200)
                    reply=request('POST','',headers=[('Cookie',sid),('X-CSRF-Token',csrf),('Origin','https://app.example')]);after=state();receipt['afterFault']=after
                    check('fresh-'+args.metadata_fault+'-actual-discovery-request',after['discovery']==before['discovery']+1,{'before':before['discovery'],'after':after['discovery']})
                    check('fresh-'+args.metadata_fault+'-closed-exact-local-session',reply[0]==503 and after['closes']==before['closes']+1 and after['sessions']==before['sessions']-1 and data(request('GET','/fixture/live',headers=[('Cookie',sid)]))['live'] is False,reply[0])
                    check('fresh-'+args.metadata_fault+'-no-save-provider-call-or-token-retry',after['saves']==before['saves'] and after['consumes']==before['consumes'] and after['logout_posts']==before['logout_posts'] and after['token_posts']==before['token_posts'])
                    check('fresh-'+args.metadata_fault+'-redacted-no-provider-delivery',not any(k.lower()=='location' for k,v in reply[1]) and b'id_token_hint' not in reply[2] and b'<form' not in reply[2] and b'TEST-ONLY-' not in reply[2] and len(cookies(reply))==2 and all('; Max-Age=0' in value for value in cookies(reply)))
                    receipt['finalState']=after;receipt['oldCauseCredit']='Original terminal503cells did not establish endpoint cause; this fresh process observes the additional discovery flight.'
                    assert all(digest(Path(path))==value for path,value in inputs.items()),'Qualification source changed during run';receipt['success']=True
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
