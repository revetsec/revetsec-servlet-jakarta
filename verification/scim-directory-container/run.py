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

"""Qualify the complete paired single-process restrictive S4 SCIM directory host in owned pinned Tomcat."""
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
    parser.add_argument("--scenario",choices=["main","small-response","expiry-write","expiry-read","rollback","keys-outage"],default="main")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    recipe = args.recipe_source or repo/"docs/ServletScimDirectoryRecipe.java"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    sources = [recipe, fixture/"ScimDirectoryServlet.java", fixture/"ScimDirectoryFixture.java"]
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
               "coreJarSha256": args.core_sha256, "adapterJarSha256": args.adapter_sha256, "sourceInputs": inputs,"scenario":args.scenario, "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Synthetic actual JWT/JWKS/KDF/current principal and volatile directory; real Servlet container; no real TLS/customer/durable/final-candidate or full S4 tool profile claim"}
    args.output.mkdir(parents=True)
    process = None
    instance = None
    current = "preparation"
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-scim-directory-"+namespace+"-") as directory:
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
                    '<web-app><servlet><servlet-name>directory</servlet-name><servlet-class>example.ScimDirectoryServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>directory</servlet-name>'
                    '<url-pattern>/scim/*</url-pattern></servlet-mapping><servlet-mapping><servlet-name>directory</servlet-name><url-pattern>/fixture/*</url-pattern></servlet-mapping></web-app>')
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
                environment["REVETSEC_SCIM_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_SCIM_RESPONSE_LIMIT"]="2048" if args.scenario=="small-response" else "65536"
                environment["REVETSEC_SCIM_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_SCIM_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_SCIM_ADAPTER_JAR"] = str(copied_adapter)
                environment["REVETSEC_SCIM_ADAPTER_SHA256"] = args.adapter_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, path if path.startswith("/fixture/") else "/scim"+path, skip_host=True, skip_accept_encoding=True)
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
                        value=data(request('GET','/fixture/control/state'));outer=value.pop('fixture');outer.update(outer.pop('directory'));outer.update(value);return outer
                    def control(command):
                        reply=request('GET','/fixture/control/'+command);assert reply[0]==200,'fixture-control-'+command;return reply
                    tokens={}
                    def token(actor,mode='valid'):
                        reply=request('GET','/fixture/token/'+actor+'/'+mode);assert reply[0]==200,'fixture-token';return data(reply)['token']
                    def api(method,path,body=None,actor='adminA',headers=(),raw=False,chunked=False,token_override=None):
                        fields=list(headers)
                        if actor is not None:
                            if actor not in tokens:tokens[actor]=token(actor)
                            fields.append(('Authorization','Bearer '+(token_override if token_override is not None else tokens[actor])))
                        payload=b''
                        if body is not None:payload=body if raw else json.dumps(body,ensure_ascii=False,separators=(',',':')).encode();fields.append(('Content-Type','application/scim+json'))
                        return request(method,path,payload,fields,chunked=chunked)
                    user_schema='urn:ietf:params:scim:schemas:core:2.0:User';group_schema='urn:ietf:params:scim:schemas:core:2.0:Group';extension='urn:example:scim:schemas:extension:Directory:2.0:User'
                    def user(external,name,display=None,password=None,label=None):
                        result={'schemas':[user_schema],'externalId':external,'userName':name,'active':True,'displayName':display or name}
                        if password is not None:result['password']=password
                        if label is not None:result['schemas'].append(extension);result[extension]={'password':label}
                        return result
                    def group(external,display,members=()):return {'schemas':[group_schema],'externalId':external,'displayName':display,'members':[{'value':value} for value in members]}
                    def patch(*operations):return {'schemas':['urn:ietf:params:scim:api:messages:2.0:PatchOp'],'Operations':list(operations)}
                    def replace(path,value):return {'op':'replace','path':path,'value':value}
                    def etag(reply):return header(reply,'etag')
                    def get(path,actor='adminA'):return api('GET',path,actor=actor)
                    def update(path,operation,version,actor='adminA'):
                        return api('PATCH',path,patch(operation),actor,[('If-Match',version)])
                    def password_matches(tenant,id,password):
                        return data(request('POST','/fixture/password/'+tenant+'/'+id,password.encode(),[('Content-Type','application/octet-stream')]))['matched']
                    def unchanged(before,reply,status):
                        after=state();return reply[0]==status and after['writes']==before['writes'] and after['rows']==before['rows'] and after['credentials']==before['credentials'] and after['charged_bytes']==before['charged_bytes']
                    def wait_blocked(count=1):
                        until=time.monotonic()+2
                        while time.monotonic()<until:
                            value=state();receipt['lastBlockedState']=value
                            if value['blocked_entered']>=count:return
                            time.sleep(.01)
                        raise AssertionError('bounded-fixture-stage-entered')
                    deadline=time.monotonic()+12
                    while True:
                        try:
                            if request('GET','/fixture/control/state')[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>deadline:raise RuntimeError('Pinned Tomcat startup failed')
                        time.sleep(.05)
                    check('selected-core-and-adapter-origins',state()['origin_verified'])
                    check('private-controls-require-credential',request('GET','/fixture/control/state',authenticated=False)[0]==401)
                    if args.scenario=='small-response':
                        before=state();document=user('e'*256,'u'*256,'d'*256,'Initial-S4-password','l'*256);document['name']={'formatted':'f'*256,'givenName':'g'*256,'familyName':'n'*256};reply=api('POST','/alpha/v2/Users',document)
                        check('response-preparation-refusal-publishes-neither-resource-nor-hash',reply[0] in [413,500,503] and state()['rows']==0 and state()['credentials']==0 and state()['writes']==0 and state()['charged_bytes']==0 and state()['sequences']==0 and state()['revisions']==0 and state()['borrowed_password_cleared'],reply[0])
                    else:
                        before=state();alice=api('POST','/alpha/v2/Users',user('alice-source','alice','Alice','Initial-S4-password','ordinary-label'))
                        check('provisioner-create-user-with-atomic-core-password-hash',alice[0]==201 and state()['writes']==before['writes']+1 and state()['credentials']==1 and state()['plaintext_credentials']==0 and state()['borrowed_password_cleared'],alice[0])
                        alice_doc=data(alice);alice_id=alice_doc['id'];alice_path='/alpha/v2/Users/'+alice_id;alice_version=etag(alice)
                        check('never-return-primary-secret-ordinary-extension-password-visible','password' not in alice_doc and alice_doc[extension]['password']=='ordinary-label' and b'Initial-S4-password' not in alice[2] and password_matches('alpha',alice_id,'Initial-S4-password'))
                        if args.scenario in ['expiry-write','expiry-read','rollback','keys-outage']:
                            before=state()
                            if args.scenario=='keys-outage':
                                check('key-outage-fresh-process-only-one-initial-flight',before['key_requests']==1,before['key_requests']);control('keys-outage');reply=get(alice_path)
                                check('actual-key-endpoint-outage-no-protected-read-or-fallback',reply[0]==503 and state()['key_requests']==before['key_requests']+1 and state()['reads']==before['reads'] and state()['writes']==before['writes'],reply[0])
                            else:
                                stage='validated' if args.scenario=='rollback' else 'before-publish';control('effect/'+stage+'/'+('rollback' if args.scenario=='rollback' else 'expire'))
                                reply=get(alice_path) if args.scenario=='expiry-read' else update(alice_path,replace('password','Replacement-S4-password'),alice_version)
                                check(args.scenario+'-exact-final-freshness-no-publication',unchanged(before,reply,401) and b'"userName"' not in reply[2] and b'"Resources"' not in reply[2] and state()['borrowed_password_cleared'],reply[0])
                                check(args.scenario+'-original-credential-preserved',password_matches('alpha',alice_id,'Initial-S4-password') and not password_matches('alpha',alice_id,'Replacement-S4-password'))
                        else:
                            bob=api('POST','/alpha/v2/Users',user('bob-source','bob','Bob'));check('second-same-tenant-resource',bob[0]==201,bob[0]);bob_id=data(bob)['id'];bob_path='/alpha/v2/Users/'+bob_id
                            beta=api('POST','/beta/v2/Users',user('beta-source','beta-secret','Beta secret'),actor='adminB');check('independent-tenant-resource',beta[0]==201,beta[0])
                            check('namespace-id-collision-remains-tenant-bound',data(beta)['id']==alice_id and '/beta/' in data(beta)['meta']['location'] and '/alpha/' in alice_doc['meta']['location'])
                            for route in ['ServiceProviderConfig','ResourceTypes','Schemas','ResourceTypes/User','Schemas/'+user_schema]:
                                reply=get('/alpha/v2/'+route);check('actual-discovery-'+route.replace('/','-'),reply[0]==200,reply[0])
                            before=state();reply=get('/beta/v2/Users')
                            check('cross-tenant-route-before-directory-snapshot',reply[0]==403 and state()['reads']==before['reads'] and state()['writes']==before['writes'])
                            before=state();reply=get('/alpha/v2/Users',actor='readerA');value=data(reply)
                            check('reader-list-count-and-projection-no-cross-tenant-leak',reply[0]==200 and value['totalResults']==2 and len(value['Resources'])==2 and b'beta-secret' not in reply[2] and all('password' not in item for item in value['Resources']))
                            check('self-cannot-read-other-user',get(bob_path,actor='selfA')[0]==404)
                            reply=get('/alpha/v2/Users?count=0',actor='selfA');check('self-collection-count-scoped-before-filter',reply[0]==200 and data(reply)['totalResults']==1 and data(reply)['Resources']==[])
                            check('self-own-resource-readable',get(alice_path,actor='selfA')[0]==200)
                            before=state();reply=update(alice_path,replace('active',True),alice_version,actor='selfA')
                            check('self-forbidden-no-op-request-denied-before-kdf',unchanged(before,reply,403) and state()['kdf_stages']==before['kdf_stages'])
                            before=state();reply=update(alice_path,replace('password','Initial-S4-password'),alice_version,actor='selfA')
                            check('self-no-password-reset-even-known-password',unchanged(before,reply,403) and state()['kdf_stages']==before['kdf_stages'])
                            before=state();reply=update(alice_path,replace('password','Initial-S4-password'),alice_version,actor='limitedA')
                            check('provisioner-credential-change-needs-explicit-field-policy',unchanged(before,reply,403) and state()['kdf_stages']==before['kdf_stages'])
                            before=state();reply=update(alice_path,replace('displayName','Alice'),alice_version,actor='readerA')
                            check('reader-cannot-write-with-write-scope',unchanged(before,reply,403) and state()['reads']==before['reads'])
                            role_token=token('readerA','role-claim-admin');reply=api('PATCH',alice_path,patch(replace('displayName','Alice')),actor='readerA',headers=[('If-Match',alice_version)],token_override=role_token)
                            check('token-role-claim-does-not-grant-current-principal-role',reply[0]==403)
                            reply=update(alice_path,replace('displayName','Alice self'),alice_version,actor='selfA');check('self-approved-display-update',reply[0]==200 and data(reply)['displayName']=='Alice self',reply[0]);alice_version=etag(reply)
                            before=state();reply=update(alice_path,replace('displayName','Alice self'),alice_version,actor='selfA');check('true-no-op-keeps-version-and-storage-charge',unchanged(before,reply,200) and etag(reply)==alice_version)
                            before=state();reply=update(alice_path,replace('password','Initial-S4-password'),alice_version);check('credential-no-op-verifies-without-version-bump',unchanged(before,reply,200) and etag(reply)==alice_version and state()['borrowed_password_cleared'])
                            before=state();reply=update(alice_path,replace('password','Replacement-S4-password'),alice_version);check('credential-rotation-atomic-hash-and-version',reply[0]==200 and etag(reply)!=alice_version and state()['writes']==before['writes']+1 and state()['plaintext_credentials']==0 and password_matches('alpha',alice_id,'Replacement-S4-password') and not password_matches('alpha',alice_id,'Initial-S4-password'));alice_version=etag(reply)
                            before=state();reply=api('PUT',alice_path,user('alice-source','alice','Alice put',label='ordinary-label'),headers=[('If-Match',alice_version)])
                            check('put-preserves-omitted-write-only-credential-without-kdf',reply[0]==200 and etag(reply)!=alice_version and state()['kdf_stages']==before['kdf_stages'] and password_matches('alpha',alice_id,'Replacement-S4-password') and state()['plaintext_credentials']==0,reply[0]);alice_version=etag(reply)
                            for name,version,extra in [('missing',None,()),('wildcard','*',()),('stale',etag(alice),()),('duplicate',alice_version,(('If-Match',alice_version),))]:
                                before=state();fields=list(extra)+([('If-Match',version)] if version else []);reply=api('PATCH',alice_path,patch(replace('displayName','blocked')),headers=fields)
                                check('exact-current-if-match-'+name,unchanged(before,reply,412),reply[0])
                            before=state();reply=api('POST','/alpha/v2/Users',user('alice-source','different'));check('external-id-unique-reconciliation-key',unchanged(before,reply,409),reply[0])
                            before=state();reply=api('POST','/alpha/v2/Users',user('another-source','ALICE'));check('ascii-casefold-username-uniqueness',unchanged(before,reply,409),reply[0])
                            for expression,total in [('userName eq "alice"',1),('active eq true and not (userName eq "bob")',1),('externalId pr',2),('userName eq "x OR 1=1"',0)]:
                                query=urllib.parse.urlencode({'filter':expression,'attributes':'id,userName','sortBy':'userName','sortOrder':'descending'});reply=get('/alpha/v2/Users?'+query)
                                check('approved-filter-execution-'+str(total)+'-'+hashlib.sha256(expression.encode()).hexdigest()[:8],reply[0]==200 and data(reply)['totalResults']==total and all(set(item)<=set(['schemas','id','userName']) for item in data(reply)['Resources']),reply[0])
                            reply=get('/alpha/v2/Users?'+urllib.parse.urlencode({'sortBy':'userName','sortOrder':'descending','startIndex':1,'count':1}));check('bounded-stable-scalar-sort-offset-page',reply[0]==200 and data(reply)['totalResults']==2 and data(reply)['Resources'][0]['userName']=='bob',reply[0])
                            reply=api('POST','/alpha/v2/Users/.search',{'schemas':['urn:ietf:params:scim:api:messages:2.0:SearchRequest'],'filter':'userName eq "bob"','attributes':['id','userName'],'count':1},actor='readerA');check('actual-search-body-uses-approved-core-plan',reply[0]==200 and data(reply)['totalResults']==1 and data(reply)['Resources'][0]['userName']=='bob',reply[0])
                            for name,query in [('secret-filter',urllib.parse.urlencode({'filter':'password pr'})),('unapproved-operator',urllib.parse.urlencode({'filter':'userName co "a"'})),('secret-sort',urllib.parse.urlencode({'sortBy':'password'})),('duplicate-count','count=1&count=2'),('filter-budget',urllib.parse.urlencode({'filter':'not '*40+'active pr'})),('cursor','cursor=untrusted')]:
                                before=state();reply=get('/alpha/v2/Users?'+query);check('query-policy-'+name,reply[0] in [400,403,413,501] and state()['writes']==before['writes'],reply[0])
                            reply=get(alice_path+'?attributes=password,'+urllib.parse.quote(extension+':password',safe=''));check('projection-never-leaks-credential-but-keeps-ordinary-label',reply[0]==200 and 'password' not in data(reply) and data(reply).get(extension,{}).get('password')=='ordinary-label' and b'Replacement-S4-password' not in reply[2],reply[0])
                            before=state();reply=api('POST','/alpha/v2/Groups',group('group-source','Team',[alice_id,bob_id]));check('same-tenant-membership-create',reply[0]==201 and state()['writes']==before['writes']+1,reply[0]);group_id=data(reply)['id'];group_path='/alpha/v2/Groups/'+group_id;group_version=etag(reply)
                            charlie=api('POST','/alpha/v2/Users',user('charlie-source','charlie'));check('third-member-resource',charlie[0]==201, charlie[0]);charlie_id=data(charlie)['id']
                            before=state();reply=api('PATCH',group_path,patch({'op':'add','path':'members','value':[{'value':charlie_id}]}),headers=[('If-Match',group_version)])
                            saved_group=get(group_path);check('authorized-member-add-handles-effective-metadata-paths',reply[0]==204 and reply[2]==b'' and state()['writes']==before['writes']+1 and saved_group[0]==200 and {item['value'] for item in data(saved_group)['members']}=={alice_id,bob_id,charlie_id},reply[0]);group_version=etag(saved_group)
                            before=state();reply=api('POST','/alpha/v2/Groups',{'schemas':[group_schema],'externalId':'foreign','displayName':'Foreign','members':[{'value':alice_id,'$ref':'https://app.example/scim/beta/v2/Users/'+alice_id}]});check('foreign-member-uri-profile-denied-no-side-effect',unchanged(before,reply,403),reply[0])
                            before=state();reply=api('DELETE',alice_path,headers=[('If-Match',alice_version)]);check('referenced-user-delete-conflicts-atomically',unchanged(before,reply,409),reply[0])
                            before=state();reply=api('PATCH',group_path,patch(replace('displayName','Not published'),{'op':'add','path':'members','value':[{'value':'missing-user'}]}),headers=[('If-Match',group_version)])
                            check('late-membership-failure-no-earlier-field-publication',unchanged(before,reply,400) and etag(get(group_path))==group_version and data(get(group_path))['displayName']=='Team',reply[0])
                            for method,path,allow in [('PUT','/alpha/v2/Users','GET, POST'),('POST',alice_path,'GET, PUT, PATCH, DELETE'),('DELETE','/alpha/v2/Users/.search','POST'),('POST','/alpha/v2/Schemas','GET')]:
                                reply=api(method,path);check('actual-target-method-allow-'+method+'-'+path.split('/')[-1],reply[0]==405 and header(reply,'allow')==allow,reply[0])
                            reply=api('HEAD',alice_path);check('head-error-status-and-body-suppression',reply[0]==405 and reply[2]==b'')
                            before=state();control('unknown-next');reply=update(alice_path,replace('displayName','Unknown applied'),alice_version)
                            check('applied-unknown-no-success-and-no-retry',reply[0]==503 and state()['writes']==before['writes']+1 and data(get(alice_path))['displayName']=='Unknown applied',reply[0]);alice_version=etag(get(alice_path))
                            before=state();control('unavailable-next');reply=update(alice_path,replace('displayName','Unavailable not applied'),alice_version)
                            check('known-unavailable-no-storage-side-effect',unchanged(before,reply,503) and etag(get(alice_path))==alice_version)
                            before=state();control('unknown-next');reply=api('POST','/alpha/v2/Users',user('unknown-create','created-after-unknown'))
                            check('unknown-create-no-success-but-one-atomic-publication',reply[0]==503 and state()['rows']==before['rows']+1 and state()['writes']==before['writes']+1)
                            query=urllib.parse.urlencode({'filter':'externalId eq \"unknown-create\"'});found=get('/alpha/v2/Users?'+query)
                            check('unknown-create-explicit-correlation-query-finds-one',found[0]==200 and data(found)['totalResults']==1);created=data(found)['Resources'][0];created_path='/alpha/v2/Users/'+created['id']
                            before=state();reply=api('POST','/alpha/v2/Users',user('unknown-create','created-after-unknown'))
                            check('explicit-create-repeat-cannot-duplicate-unknown-effect',unchanged(before,reply,409))
                            version=etag(get(created_path));before=state();reply=api('DELETE',created_path,headers=[('If-Match',version)])
                            check('delete-confirmed-atomic-and-empty',reply[0]==204 and reply[2]==b'' and state()['rows']==before['rows']-1 and get(created_path)[0]==404)
                            # Raw admission failures must precede public JWT/key/account/store work.
                            for name,fields,path,status in [
                                    ('missing-bearer',[],alice_path,401),
                                    ('duplicate-bearer',[('Authorization','Bearer '+tokens['adminA']),('Authorization','Bearer '+tokens['adminA'])],alice_path,400),
                                    ('comma-bearer',[('Authorization','Bearer '+tokens['adminA']+',Bearer '+tokens['adminA'])],alice_path,400),
                                    ('cookie-bearer',[('Authorization','Bearer '+tokens['adminA']),('Cookie','access_token=untrusted')],alice_path,400),
                                    ('query-bearer',[('Authorization','Bearer '+tokens['adminA'])],alice_path+'?access_token=untrusted',400),
                                    ('encoded-query-bearer',[('Authorization','Bearer '+tokens['adminA'])],alice_path+'?%61ccess_token=untrusted',400),
                                    ('duplicate-origin',[('Authorization','Bearer '+tokens['adminA']),('Origin','https://app.example'),('Origin','https://app.example')],alice_path,403),
                                    ('untrusted-origin',[('Authorization','Bearer '+tokens['adminA']),('Origin','https://wrong.invalid')],alice_path,403),
                                    ('insecure-carrier',[('Authorization','Bearer '+tokens['adminA']),('X-Fixture-Carrier','insecure')],alice_path,400)]:
                                before=state();reply=request('GET',path,headers=fields)
                                check('raw-admission-'+name,unchanged(before,reply,status) and state()['admissions']==before['admissions'] and state()['key_requests']==before['key_requests'] and state()['reads']==before['reads'],reply[0])
                            for mode,status in [('wrong-key',401),('wrong-issuer',401),('wrong-audience',401),('expired',401),('future',401),('unmapped',401),('missing-client',401),('missing-tenant',401),('wrong-tenant',403),('no-scope',403),('wrong-type',401)]:
                                invalid=token('adminA',mode);before=state();reply=api('GET',alice_path,token_override=invalid)
                                check('actual-signed-token-profile-'+mode,unchanged(before,reply,status) and state()['reads']==before['reads'],reply[0])
                            before=state();reply=api('PATCH',alice_path,patch(replace('displayName','denied')),headers=[('If-Match',alice_version)],token_override=token('adminA','read-only'))
                            check('signed-read-scope-does-not-authorize-mutation',unchanged(before,reply,403) and state()['reads']==before['reads'])
                            before=state();control('admission-deny');reply=get(alice_path);control('admission-allow')
                            check('application-admission-denial-precedes-account-data-work',unchanged(before,reply,403) and state()['reads']==before['reads'] and state()['kdf_stages']==before['kdf_stages'])
                            for name,body,fields,chunked,status in [('declared-overlimit',b' '*16385,[],False,413),('streamed-overlimit',b' '*16385,[],True,413),('stream-unavailable',b'{}',[('X-Fixture-Carrier','stream-io')],False,503),('malformed-json',b'{',[],False,400),('duplicate-media',b'{}',[('Content-Type','application/scim+json')],False,415)]:
                                before=state();reply=api('POST','/alpha/v2/Users',body,headers=fields,raw=True,chunked=chunked)
                                check('bounded-body-'+name,unchanged(before,reply,status),reply[0])
                            before=state();reply=request('GET',alice_path,b'not-empty',[('Authorization','Bearer '+tokens['adminA'])])
                            check('get-body-denied-before-account-work',unchanged(before,reply,400) and state()['reads']==before['reads'])
                            before=state();reply=api('PATCH',alice_path,patch(*[replace('displayName','op'+str(i)) for i in range(17)]),headers=[('If-Match',alice_version)])
                            check('patch-operation-budget-no-partial-publication',reply[0] in [400,413] and state()['writes']==before['writes'] and state()['charged_bytes']==before['charged_bytes'],reply[0])
                            before=state();control('credential-deny');reply=update(alice_path,replace('password','Policy-rejected-password'),alice_version);control('credential-allow')
                            check('credential-policy-denial-before-kdf-and-publication',unchanged(before,reply,400) and state()['kdf_stages']==before['kdf_stages'] and state()['borrowed_password_cleared'])
                            for stage,mode,status in [('before-kdf','no-credential',403),('before-prepare','reader',403),('before-publish','tenant-beta',403),('before-publish','late',503),('before-kdf','interrupt',503),('before-kdf','checked-interrupt',503),('before-kdf','checked-io',503),('before-kdf','timeout',503)]:
                                before=state();control('effect/'+stage+'/'+mode);reply=update(alice_path,replace('password','Denied-'+mode),alice_version);after=state()
                                check('post-collaborator-'+stage+'-'+mode,unchanged(before,reply,status) and after['borrowed_password_cleared'] and b'"userName"' not in reply[2] and b'"Resources"' not in reply[2],reply[0])
                                if 'interrupt' in mode or mode=='checked-io':check('restored-interruption-'+mode,after['interrupt_observed'] and after['handler_interrupt_left_set'] and after['handler_cancel_no_publication'])
                                if mode=='timeout':check('timeout-does-not-invent-thread-interruption',not after['last_handler_interrupt_set'])
                                control('reset-policy');control('clear-late')
                            check('collaborator-refusals-preserve-original-credential',password_matches('alpha',alice_id,'Replacement-S4-password') and not password_matches('alpha',alice_id,'Denied-no-credential'))
                            for operation,status in [({'op':'replace','value':{'active':True}},403),({'op':'add','value':{'password':'Hidden password'}},403),({'op':'remove','path':'password'},403)]:
                                before=state();reply=api('PATCH',alice_path,patch(operation),actor='selfA',headers=[('If-Match',alice_version)])
                                check('requested-pathless-or-remove-field-policy-'+operation['op'],unchanged(before,reply,status) and state()['kdf_stages']==before['kdf_stages'],reply[0])
                            for operation in [{'op':'remove','path':'password'},replace('password',None)]:
                                before=state();reply=api('PATCH',alice_path,patch(operation),headers=[('If-Match',alice_version)])
                                check('credential-removal-null-refused-'+operation['op'],unchanged(before,reply,400) and state()['kdf_stages']==before['kdf_stages'],reply[0])
                            before=state();reply=request('GET',alice_path,headers=[('Authorization','Bearer '+tokens['adminA']),('Host','wrong.invalid')])
                            check('actual-container-duplicate-host-refused',unchanged(before,reply,400) and state()['admissions']==before['admissions'],reply[0])
                            before=state();reply=request('GET',alice_path,headers=[('Authorization','Bearer '+tokens['adminA']),('X-Fixture-Carrier','insecure'),('X-Forwarded-Proto','https'),('Forwarded','proto=https;host=app.example')])
                            check('forwarded-headers-do-not-upgrade-untrusted-transport',unchanged(before,reply,400) and state()['admissions']==before['admissions'])
                            # Actual blocked collaborator, not a lock-held simulation: unrelated GET completes.
                            control('block/before-kdf/1');before=state()
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                                pending=pool.submit(update,alice_path,replace('password','Race-password'),alice_version);wait_blocked()
                                observed=get(bob_path,actor='readerA');check('credential-collaborator-outside-directory-version-lock',observed[0]==200 and state()['writes']==before['writes'])
                                control('policy-reader');control('release');reply=pending.result(timeout=5)
                            check('current-policy-change-during-blocked-kdf-withholds-hash',unchanged(before,reply,403) and state()['borrowed_password_cleared'] and password_matches('alpha',alice_id,'Replacement-S4-password'),reply[0]);control('reset-policy')
                            control('block/before-publish/2');before=state()
                            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                                pending=[pool.submit(update,alice_path,replace('displayName',value),alice_version) for value in ['Race one','Race two']];wait_blocked(2);control('release');outcomes=[item.result(timeout=5) for item in pending]
                            current_alice=get(alice_path);check('same-version-race-one-atomic-publication',sorted(item[0] for item in outcomes)==[200,412] and state()['writes']==before['writes']+1 and data(current_alice)['displayName'] in ['Race one','Race two'] and etag(current_alice)!=alice_version,[item[0] for item in outcomes]);alice_version=etag(current_alice)
                            control('block/before-publish/1');before=state()
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                                pending=pool.submit(get,alice_path,'readerA');wait_blocked();changed=update(alice_path,replace('displayName','Current after read'),alice_version);control('release');reply=pending.result(timeout=5)
                            check('prepared-stale-read-withheld-after-concurrent-commit',changed[0]==200 and reply[0]==503 and b'"userName"' not in reply[2] and state()['writes']==before['writes']+1,reply[0]);alice_version=etag(changed)
                            dave=api('POST','/alpha/v2/Users',user('dave-source','dave'));check('membership-race-user-created',dave[0]==201);dave_id=data(dave)['id'];dave_path='/alpha/v2/Users/'+dave_id;dave_version=etag(dave)
                            group_version=etag(get(group_path));control('block/before-publish/2');before=state()
                            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                                addition=pool.submit(api,'PATCH',group_path,patch({'op':'add','path':'members','value':[{'value':dave_id}]}),'adminA',[('If-Match',group_version)])
                                deletion=pool.submit(api,'DELETE',dave_path,None,'adminA',[('If-Match',dave_version)]);wait_blocked(2);control('release');outcomes=[addition.result(timeout=5),deletion.result(timeout=5)]
                            saved=get(group_path);ids={item['value'] for item in data(saved)['members']};live=get(dave_path)
                            check('membership-and-user-delete-race-never-dangles',sorted(item[0] for item in outcomes)==[204,412] and state()['writes']==before['writes']+1 and ((dave_id in ids and live[0]==200) or (dave_id not in ids and live[0]==404)),[item[0] for item in outcomes])
                            control('block/before-prepare/8');before=state()
                            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                                pending=[pool.submit(get,bob_path,'readerA') for _ in range(8)];wait_blocked(8);held=state();ninth=get(bob_path,'readerA')
                                check('eight-permits-ninth-refused-before-expensive-work',ninth[0]==503 and state()['admissions']==held['admissions'] and state()['reads']==held['reads'] and state()['writes']==before['writes'],ninth[0]);control('release');outcomes=[item.result(timeout=5) for item in pending]
                            check('all-eight-admitted-reads-complete-and-permits-recover',all(item[0]==200 for item in outcomes) and get(bob_path,'readerA')[0]==200,[item[0] for item in outcomes])
                            # Fill only this owned tenant; refusal neither evicts nor consumes an ID/version.
                            created_paths=[]
                            while data(get('/alpha/v2/Users?count=0'))['totalResults']+data(get('/alpha/v2/Groups?count=0'))['totalResults']<64:
                                index=len(created_paths);reply=api('POST','/alpha/v2/Users',user('capacity-'+str(index),'capacity-'+str(index)));assert reply[0]==201,'capacity-fill-confirmed';created_paths.append('/alpha/v2/Users/'+data(reply)['id'])
                            before=state();reply=api('POST','/alpha/v2/Users',user('capacity-overflow','capacity-overflow'))
                            check('tenant-row-cap-refuses-without-eviction-or-id-consumption',unchanged(before,reply,503) and state()['sequences']==before['sequences'] and state()['revisions']==before['revisions'] and get(alice_path)[0]==200 and get('/beta/v2/Users',actor='readerB')[0]==200,reply[0])
                            removed=created_paths[-1];version=etag(get(removed));before=state();reply=api('DELETE',removed,headers=[('If-Match',version)]);after=state()
                            check('delete-reclaims-exact-row-and-byte-admission',reply[0]==204 and after['rows']==before['rows']-1 and after['charged_bytes']<before['charged_bytes'] and after['credentials']==before['credentials'])
                            reply=api('POST','/alpha/v2/Users',user('capacity-recovered','capacity-recovered'));check('capacity-recovery-after-delete-without-eviction',reply[0]==201 and get(alice_path)[0]==200)
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
