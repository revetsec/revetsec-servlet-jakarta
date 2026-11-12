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
                    def bootstrap():
                        reply=request('POST','/fixture/login',b'begin=1',[("Content-Type","application/x-www-form-urlencoded")]);assert reply[0]==200,'genuine-fixture-login'
                        assert data(reply)['genuine_authentication'] is True,'actual-op-pkce-signature-before-session'
                        return {'cookie':cookie(reply,'__Host-app-session'),'csrf':data(reply)['csrf']}
                    def live(browser):return data(request('GET','/fixture/live',headers=[('Cookie',browser['cookie'])]))['live']
                    def start(browser,path='',body=b'',extra=(),method='POST',headers_override=None,chunked=False):
                        headers=headers_override if headers_override is not None else [('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','https://app.example')]
                        return request(method,path,body,[*headers,*extra],chunked=chunked)
                    def clear_cookie(reply,name):return any(c.startswith(name+'=;') and 'Max-Age=0' in c for c in cookies(reply))
                    def no_delivery(reply):return not any(k.lower()=='location' for k,v in reply[1]) and b'id_token_hint' not in reply[2] and not any(c.startswith('__Host-rp-logout=') and not c.startswith('__Host-rp-logout=;') for c in cookies(reply))
                    class Form(html.parser.HTMLParser):
                        def __init__(self):super().__init__();self.action=None;self.fields={}
                        def handle_starttag(self,tag,attrs):
                            values=dict(attrs)
                            if tag=='form':self.action=values.get('action')
                            if tag=='input' and 'name' in values:self.fields[values['name']]=values.get('value','')
                    def prepared(reply):
                        if args.delivery=='form':
                            assert reply[0]==200,'form-delivered';parsed=Form();parsed.feed(reply[2].decode());action=parsed.action;fields=parsed.fields
                        else:
                            assert reply[0]==303,'trusted-get-delivered';uri=urllib.parse.urlsplit(header(reply,'location'));action=urllib.parse.urlunsplit((uri.scheme,uri.netloc,uri.path,'',''));fields=dict(urllib.parse.parse_qsl(uri.query,strict_parsing=True));assert len(header(reply,'location'))<=4096,'bounded-get-uri'
                        uri=urllib.parse.urlsplit(action);assert uri.scheme=='http' and uri.hostname=='127.0.0.1' and uri.path=='/logout' and uri.port,'owned-synthetic-provider-only'
                        assert fields['post_logout_redirect_uri']=='https://app.example/logout/callback' and len(fields['state'])==43 and len(fields['id_token_hint'])>100,'genuine-hint-and-fixed-correlation'
                        return {'pending':cookie(reply,'__Host-rp-logout'),'state':fields['state'],'action':action,'fields':fields}
                    def callback(tx,query=None,extra=(),newer=None):
                        return request('GET','/callback?'+(query if query is not None else urllib.parse.urlencode({'state':tx['state']})),headers=[('Cookie',tx['pending']+(';' + newer['cookie'] if newer else '')),*extra])
                    def redacted(reply):return all(value not in reply[2] for value in [b'TEST-ONLY-close-secret',b'TEST-ONLY-store-secret',b'id_token_hint'])
                    deadline=time.monotonic()+12
                    while True:
                        try:
                            if request('GET','/fixture/control/state')[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>deadline:raise RuntimeError('Pinned Tomcat startup failed')
                        time.sleep(.05)
                    check('actual-selected-core-common-fixture-origins',state()['origin_verified'])
                    check('fixture-controls-require-credential',request('GET','/fixture/control/state',authenticated=False)[0]==401)
                    browser=bootstrap();before=state()
                    check('genuine-oidc-login-before-fixture-session',live(browser) and before['token_posts']==1)
                    if args.padding:
                        reply=start(browser)
                        if args.delivery=='get':check('get-hint-uri-overflow-local-first-no-save',reply[0]==503 and not live(browser) and state()['saves']==before['saves'] and clear_cookie(reply,'__Host-app-session') and no_delivery(reply))
                        else:
                            tx=prepared(reply);check('large-form-hint-remains-bounded-and-correlated',len(reply[2])>6000 and len(reply[2])<131072 and not live(browser) and callback(tx)[0]==200)
                    else:
                        cases=[('get-method','',b'',(),'GET',None,405),('head-method','',b'',(),'HEAD',None,405),('bare-query','?',b'',(),'POST',None,400),('query','?state=attacker',b'',(),'POST',None,400),('body','',b'x',(),'POST',None,400),('body-cap-plus-one','',b'x'*4097,(),'POST',None,413),('wrong-origin','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','https://wrong.invalid')],403),('null-origin','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','null')],403),('missing-origin','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf'])],403),('wrong-csrf','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token','A'*43),('Origin','https://app.example')],403),('duplicate-csrf','',b'',(('X-CSRF-Token',browser['csrf']),),'POST',None,400),('duplicate-origin','',b'',(('Origin','https://app.example'),),'POST',None,403),('duplicate-cookie','',b'',(('Cookie',browser['cookie']),),'POST',None,400),('authorization','',b'',(('Authorization','Bearer invalid'),),'POST',None,400),('duplicate-media','',b'',(('Content-Type','application/x-www-form-urlencoded'),('Content-Type','application/x-www-form-urlencoded')),'POST',None,415),('bad-media','',b'',(('Content-Type','application/json'),),'POST',None,415),('insecure-connector','',b'',(('X-Fixture-Carrier','insecure'),),'POST',None,400),('stream-io','',b'',(('X-Fixture-Carrier','stream-io'),),'POST',None,503),('header-individual-budget','',b'',(('X-Large','x'*4097),),'POST',None,400),('header-total-budget','',b'',tuple(('X-Large-'+str(i),'x'*3000) for i in range(3)),'POST',None,400),('header-occurrence-budget','',b'',tuple(('X-Duplicate','x') for _ in range(33)),'POST',None,400),('encoded-route','/%63allback',b'',(),'POST',None,400)]
                        for name,path,body,extra,method,headers_override,status in cases:
                            before=state();reply=start(browser,path,body,extra,method,headers_override)
                            check('carrier-'+name+'-before-local-close',reply[0]==status and live(browser) and state()['closes']==before['closes']+(1 if name=='wrong-csrf' else 0) and state()['saves']==before['saves'] and no_delivery(reply),reply[0])
                            if method=='HEAD':check('head-suppresses-error-body',reply[2]==b'')
                        before=state();reply=start(browser,extra=[('X-Fixture-Carrier','stream-interrupt')])
                        check('interrupted-input-preserves-flag-before-fixture-clear',reply[0]==503 and live(browser) and state()['closes']==before['closes'] and state()['handler_interrupt_left_set'] and state()['handler_cancel_no_publication'])
                        reply=start(browser,extra=[('X-Fixture-Carrier','stream-timeout')]);check('socket-timeout-does-not-invent-interruption',reply[0]==503 and live(browser) and state()['timeout_observed'] and not state()['timeout_interrupt_set'])
                        before=state();reply=start(browser,body=b'x'*4097,chunked=True)
                        check('chunked-overflow-not-valid-prefix',reply[0]==413 and live(browser) and state()['closes']==before['closes'] and no_delivery(reply))
                        before=state();reply=start(browser,extra=[('Host','app.example')])
                        check('container-physical-host-duplicate-refuses',reply[0]==400 and live(browser) and state()['closes']==before['closes'])
                        before=state();reply=start(browser);tx=prepared(reply)
                        check('local-first-delivery-after-genuine-session-close',not live(browser) and state()['closes']==before['closes']+1 and state()['saves']==before['saves']+1 and state()['logout_posts']==before['logout_posts'])
                        check('separate-session-and-pending-cookie-fields',len(cookies(reply))==2 and clear_cookie(reply,'__Host-app-session') and all('Secure' in c and 'HttpOnly' in c and 'Path=/' in c and 'SameSite=Lax' in c for c in cookies(reply)))
                        check('no-referrer-no-store-bounded-emission',header(reply,'cache-control')=='no-store' and header(reply,'referrer-policy')=='no-referrer' and int(header(reply,'content-length'))==len(reply[2]))
                        if args.delivery=='form':check('fixed-origin-csp-escaped-form',b'<form method="post"' in reply[2] and 'form-action http://127.0.0.1:' in header(reply,'content-security-policy'))
                        before=state();reply=start(browser)
                        check('closed-session-no-retry-or-reattach',reply[0]==403 and not live(browser) and state()['saves']==before['saves'] and no_delivery(reply))
                        newer=bootstrap();before=state();reply=callback(tx,newer=newer)
                        check('state-only-return-is-correlation-not-session-proof',reply[0]==200 and b'provider-session termination is not confirmed' in reply[2] and clear_cookie(reply,'__Host-rp-logout') and not clear_cookie(reply,'__Host-app-session') and live(newer))
                        check('pending-consumed-once-no-provider-call',state()['consumes']==before['consumes']+1 and state()['logout_posts']==before['logout_posts'])
                        check('return-replay-refused-newer-session-survives',callback(tx,newer=newer)[0]==400 and live(newer))
                        for name,query,body,extra,status in [('missing-state','',b'',(),400),('bare-query','',b'',(),400),('duplicate-state','state='+tx['state']+'&state='+tx['state'],b'',(),400),('encoded-duplicate-state','state='+tx['state']+'&%73tate='+tx['state'],b'',(),400),('extra-credential','state='+tx['state']+'&id_token=untrusted',b'',(),400),('body','state='+tx['state'],b'x',(),400),('overflow','state='+tx['state'],b'x'*4097,(),413),('stream-io','state='+tx['state'],b'',(('X-Fixture-Carrier','stream-io'),),503),('header-budget','state='+tx['state'],b'',(('X-Large','x'*4097),),400)]:
                            before=state();reply=request('GET','/callback?'+query,body,[('Cookie',tx['pending']+';'+newer['cookie']),*extra])
                            check('callback-'+name+'-clears-only-pending',reply[0]==status and clear_cookie(reply,'__Host-rp-logout') and not clear_cookie(reply,'__Host-app-session') and live(newer) and no_delivery(reply),reply[0])
                        # An invalid browser binding is not correlation and cannot establish provider termination.
                        fresh=bootstrap();started=start(fresh);pending=prepared(started);before=state()
                        wrong=dict(pending);wrong['pending']='__Host-rp-logout='+'B'*42+'A';reply=callback(wrong,newer=newer)
                        check('wrong-browser-binding-no-provider-correlation',reply[0]==400 and live(newer) and no_delivery(reply))
                        check('exact-browser-binding-can-correlate',callback(pending,newer=newer)[0]==200 and live(newer))
                        for mode in ['throw-before','throw-after','unavailable-before','unavailable-after','late','interrupt']+(['checked-interrupt','checked-io-interrupt','checked-timeout'] if args.fixture_supplement else []):
                            control('reset-modes');fresh=bootstrap();control('close/'+mode);before=state();reply=start(fresh);after=state()
                            expected_live=mode in ['throw-before','unavailable-before']
                            check('close-'+mode+'-no-provider-or-retry',reply[0]==503 and live(fresh)==expected_live and after['closes']==before['closes']+1 and after['saves']==before['saves'] and clear_cookie(reply,'__Host-app-session') and no_delivery(reply) and redacted(reply),reply[0])
                            if mode.startswith('checked-'):check('checked-close-thread-state-'+mode,after['last_handler_interrupt_set']==(mode!='checked-timeout') and (mode=='checked-timeout' or after['handler_interrupt_left_set'] and after['handler_cancel_no_publication']))
                        for mode in ['UNAVAILABLE','CAPACITY_REFUSED','ALREADY_PRESENT','INDETERMINATE','throw-before','throw-after','null','late','interrupt']:
                            control('reset-modes');fresh=bootstrap();control('save/'+mode);before=state();reply=start(fresh);after=state()
                            check('save-'+mode+'-local-ended-no-success',reply[0]==503 and not live(fresh) and after['closes']==before['closes']+1 and after['saves']==before['saves']+1 and clear_cookie(reply,'__Host-app-session') and clear_cookie(reply,'__Host-rp-logout') and no_delivery(reply) and redacted(reply),reply[0])
                        for mode in ['throw-before','throw-after','null','late','interrupt']:
                            control('reset-modes');fresh=bootstrap();pending=prepared(start(fresh));control('consume/'+mode);before=state();reply=callback(pending,newer=newer);after=state()
                            check('consume-'+mode+'-no-success-or-session-revival',reply[0] in [400,503] and not live(fresh) and live(newer) and after['consumes']==before['consumes']+1 and clear_cookie(reply,'__Host-rp-logout') and not clear_cookie(reply,'__Host-app-session') and no_delivery(reply) and redacted(reply),reply[0])
                        check('explicit-fixture-cancellation-observed-before-clear',state()['interrupt_observed'] and state()['handler_interrupt_left_set'] and state()['handler_cancel_no_publication'])
                        if args.fixture_supplement:
                            def wait_blocked(count):
                                until=time.monotonic()+2
                                while time.monotonic()<until:
                                    value=state();receipt['lastBlockedState']=value
                                    if value['blocked_entered']>=count:return
                                    time.sleep(.01)
                                raise AssertionError('bounded-fixture-latch-entered')
                            control('reset-modes');browsers=[bootstrap() for _ in range(9)];before=state();control('block-save')
                            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                                held=[workers.submit(start,browser) for browser in browsers[:8]]
                                try:
                                    wait_blocked(8);busy=start(browsers[8]);during=state()
                                    check('ninth-start-before-close-or-cookie-effect',busy[0]==503 and live(browsers[8]) and not cookies(busy) and during['closes']==before['closes']+8 and during['saves']==before['saves']+8 and during['block_peak']==8)
                                finally:control('release')
                                done=[future.result(timeout=5) for future in held]
                            check('eight-admitted-saves-deliver-after-release',all(reply[0]==(200 if args.delivery=='form' else 303) for reply in done) and all(not live(browser) for browser in browsers[:8]) and state()['saves']==before['saves']+8)
                            check('ninth-start-can-explicitly-run-after-permit-return',start(browsers[8])[0]==(200 if args.delivery=='form' else 303) and not live(browsers[8]) and state()['saves']==before['saves']+9)
                            control('reset-modes');transactions=[prepared(start(bootstrap())) for _ in range(9)];fresh=bootstrap();before=state();control('block-consume')
                            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                                held=[workers.submit(callback,tx) for tx in transactions[:8]]
                                try:
                                    wait_blocked(8);busy=callback(transactions[8],newer=newer);during=state()
                                    check('ninth-callback-before-consume-clears-only-pending',busy[0]==503 and during['consumes']==before['consumes']+8 and clear_cookie(busy,'__Host-rp-logout') and not clear_cookie(busy,'__Host-app-session') and live(newer))
                                    refused=start(fresh);check('callbacks-share-admission-with-starts',refused[0]==503 and live(fresh) and not cookies(refused) and state()['closes']==before['closes'])
                                finally:control('release')
                                done=[future.result(timeout=5) for future in held]
                            check('eight-admitted-returns-correlate-after-release',all(reply[0]==200 for reply in done) and state()['consumes']==before['consumes']+8)
                            check('ninth-return-explicit-after-permit-return',callback(transactions[8],newer=newer)[0]==200 and live(newer) and state()['consumes']==before['consumes']+9)
                            control('reset-modes');tx=prepared(start(bootstrap()));before=state();control('block-consume')
                            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                                held=[workers.submit(callback,tx) for _ in range(2)]
                                try:wait_blocked(2)
                                finally:control('release')
                                done=[future.result(timeout=5) for future in held]
                            check('duplicate-return-race-atomic-one-use',sorted(reply[0] for reply in done)==[200,400] and state()['consumes']==before['consumes']+2 and live(newer))
                        control('reset-modes');fresh=bootstrap();pending=prepared(start(fresh));control('clock/expiry');reply=callback(pending,newer=newer)
                        check('expired-return-no-termination-or-local-revival',reply[0]==400 and not live(fresh) and live(newer) and no_delivery(reply))
                        control('reset-modes');fresh=bootstrap();control('metadata/'+args.metadata_fault);before=state();reply=start(fresh)
                        check('metadata-'+args.metadata_fault+'-keeps-local-first-without-save',reply[0]==503 and not live(fresh) and state()['saves']==before['saves'] and clear_cookie(reply,'__Host-app-session') and no_delivery(reply) and redacted(reply),reply[0])
                    receipt['finalState']=state();assert all(digest(Path(path))==value for path,value in inputs.items()),'Qualification source changed during run';receipt['success']=True
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
