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

"""Qualify actual paired Servlet issuer HTTP composition with owned disposable PostgreSQL."""
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
import base64
import struct
import select
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
    parser.add_argument("--durable-recipe-source",type=Path)
    parser.add_argument("--workflow-source",type=Path)
    parser.add_argument("--reference-store-source-root",type=Path)
    parser.add_argument("--fixture-source", type=Path, help="Private exact source calibration override")
    parser.add_argument("--servlet-source", type=Path, help="Private exact carrier calibration override")
    for name in ["store","pyranid","driver"]:
        parser.add_argument("--"+name+"-jar",type=Path,required=True)
        parser.add_argument("--"+name+"-sha256",required=True)
    parser.add_argument("--checker-qual-jar",type=Path,required=True)
    parser.add_argument("--annotations-repository", type=Path, default=Path.home()/".m2/repository")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    recipes=[args.durable_recipe_source or repo/"docs/ServletDurableBackendRecipe.java",args.workflow_source or repo/"docs/ServletWorkflowRecipes.java"]
    pg=args.reference_store_source_root or repo.parent/"revetsec/examples/postgresql-pending-store"
    schema=pg/"issuer-schema.sql"
    store_sources=sorted((pg/"src/main/java").rglob("*.java"))
    required_store_sources=[pg/"src/main/java/example/pending"/name for name in ["PostgresqlIssuerStore.java","IssuerPgScope.java","IssuerPgLocks.java","IssuerPgCapacity.java","IssuerPgTransactions.java"]]
    image="sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    new_sources=[args.servlet_source or fixture/"DurableIssuerServlet.java",args.fixture_source or fixture/"DurableIssuerFixture.java"]
    sources=[*recipes,*new_sources]
    selected={"CORE":(args.core_jar,args.core_sha256),"ADAPTER":(args.adapter_jar,args.adapter_sha256),"STORE":(args.store_jar,args.store_sha256),"PYRANID":(args.pyranid_jar,args.pyranid_sha256),"DRIVER":(args.driver_jar,args.driver_sha256)}
    auditor = repo/"verification/nullability/NullabilityAudit.java"
    for item in [args.tomcat_archive,*[p for p,h in selected.values()],args.checker_qual_jar,*annotations,*sources,auditor,pins_path,schema,*required_store_sources,*store_sources]:
        if not item.is_file(): parser.error("Required input missing: "+str(item))
    for name,(path,expected)in selected.items():
        if not re.fullmatch("[0-9a-f]{64}",expected)or digest(path)!=expected:parser.error("Selected "+name+" SHA256 mismatch before resources")
    if digest(args.checker_qual_jar)!="857658c8bdcbff794949a8d9922f88d63ee3751c203c7cd7d21ea97f9e745288":parser.error("Compile-only manifest annotation pin mismatch")
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive differs from reviewed SHA512")
    if args.output.exists(): parser.error("Use a fresh evidence output directory")
    inputs = {str(p.resolve()): digest(p) for p in [*sources,auditor,pins_path,Path(__file__),schema,*store_sources]}
    receipt = {"namespace": namespace, "runtime": pins["version"], "runtimeSha512": pins["archiveSha512"],
               "coreJarSha256":args.core_sha256,"adapterJarSha256":args.adapter_sha256,"selectedArtifacts":{n:{"path":str(p),"sha256":h}for n,(p,h)in selected.items()},"sourceInputs":inputs,"postgresImage":image,"ownedDatabaseRemoved":False,"databaseSnapshots":[],"serverPhases":[], "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Actual current issuer/Servlet/reference-store HTTP composition with private synthetic account, independent scripted authority and owned PostgreSQL; no approved UTC, fullC, cross-host, browser/TLS/deployment/formal-tool/final package proof"}
    args.output.mkdir(parents=True)
    process = None
    instance=None;resource="revetsec-servlet-issuer-"+secrets.token_hex(6);volume=resource+"-data";network=resource+"-network";created=[];db_password=secrets.token_urlsafe(32);runtime_password=secrets.token_urlsafe(32)
    current="preparation"
    def docker(*command,data=None,timeout=45):
        completed=subprocess.run(["docker",*command],input=data,capture_output=True,text=True,timeout=timeout)
        if completed.returncode:raise RuntimeError("Owned Docker operation failed: "+command[0])
        return completed.stdout.strip()
    def sql(text):return docker("exec","-i",resource,"psql","-X","-qAt","-v","ON_ERROR_STOP=1","-U","postgres","-d","qualification",data=text)
    def identity(value):return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")
    def admission_lock():
        physical=identity("issuer-physical/servlet_issuer").encode();value=hashlib.sha256(b"revetsec/pg-admission/v1\0"+struct.pack("!I",6)+b"ISSUER"+struct.pack("!I",len(physical))+physical).digest();first,second=struct.unpack("!ii",value[:8]);return "SELECT pg_advisory_xact_lock("+str(first)+","+str(second)+");"
    def snapshot(label):
        raw=sql("SELECT coalesce(json_agg(row_to_json(x)ORDER BY storage_key),'[]')FROM(SELECT storage_key,kind,version,retain_seconds,retain_nanos,encode(sha256(convert_to(sealed_form,'UTF8')),'hex') AS form_sha256 FROM issuer_store_entry WHERE namespace='servlet_issuer')x;")
        rows=json.loads(raw);quotas=json.loads(sql("SELECT json_agg(row_to_json(x)ORDER BY bucket) FROM(SELECT bucket,allocation_generation,entry_limit,used_entries,used_bytes,byte_limit FROM issuer_store_escrow WHERE namespace='"+identity("issuer-physical/servlet_issuer")+"')x;"));assert len(quotas)==256,"all256escrows-observed"
        counts={kind:sum(r["kind"]==kind for r in rows)for kind in ["ISSUER_STATE","SUBJECT_STATE","INTERACTION","CODE","GRANT","ACCESS_TOKEN","REFRESH_TOKEN"]};usage=[0]*256
        for row in rows:usage[hashlib.sha256(row["storage_key"].encode()).digest()[0]]+=1
        assert all(q["used_entries"]==usage[q["bucket"]]and q["used_bytes"]==0 for q in quotas),"independent-all256quota-accounting"
        value={"label":label,"rows":rows,"quotas":quotas,"counts":counts,"stateSha256":hashlib.sha256((raw+json.dumps(quotas,sort_keys=True)).encode()).hexdigest()};receipt["databaseSnapshots"].append(value);return value
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-durable-issuer-"+namespace+"-") as directory:
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
                runtime_jars={}
                for name,(original,expected)in selected.items():
                    copied=base/"webapps/ROOT/WEB-INF/lib"/(name.lower()+".jar");shutil.copyfile(original,copied)
                    if digest(copied)!=expected:raise RuntimeError("Selected artifact changed during copy")
                    runtime_jars[name]=copied
                # The unpublished normal store JAR has manifest Class-Path entries. Supply exact
                # links for javac only; runtime WAR has only the five explicitly selected JARs.
                compile_inputs=instance/"compile-inputs";compile_inputs.mkdir();compile_store=compile_inputs/"store.jar";shutil.copyfile(args.store_jar,compile_store);links=compile_inputs/"lib";links.mkdir()
                for name,p in [("revetsec-1.0.0-SNAPSHOT.jar",args.core_jar),("pyranid-4.7.0.jar",args.pyranid_jar),("postgresql-42.7.14.jar",args.driver_jar),("checker-qual-3.55.1.jar",args.checker_qual_jar)]:shutil.copyfile(p,links/name)
                classpath=os.pathsep.join(map(str,[args.core_jar,args.adapter_jar,compile_store,args.pyranid_jar,args.driver_jar,home/"lib/servlet-api.jar",*annotations]))
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
                (instance/"sources.txt").write_text("".join(str(p)+"\n" for p in new_sources))
                (instance/"classpath.txt").write_text(str(classes)+os.pathsep+classpath)
                audited = subprocess.run([str(args.java_home/"bin/java"), "-cp", os.pathsep.join(map(str, [audit_classes, *annotations])),
                    "NullabilityAudit", str(instance/"sources.txt"), str(instance/"classpath.txt"), str(args.output/"nullability.json")], capture_output=True, text=True)
                (args.output/"audit.log").write_text(audited.stdout+audited.stderr)
                if audited.returncode: raise RuntimeError("Explicit source nullability audit failed")
                receipt["checks"].append({"name": "explicit-nullability-attributed", "passed": True})
                (base/"webapps/ROOT/WEB-INF/web.xml").write_text(
                    '<web-app><servlet><servlet-name>issuer</servlet-name><servlet-class>example.DurableIssuerServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>issuer</servlet-name>'
                    '<url-pattern>/issuer/*</url-pattern></servlet-mapping></web-app>')
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
                credential=secrets.token_urlsafe(32);environment=dict(os.environ);environment.pop("JAVA_TOOL_OPTIONS",None);environment.pop("JDK_JAVA_OPTIONS",None)
                environment["REVETSEC_DURABLE_FIXTURE_CREDENTIAL"]=credential
                for name,p in runtime_jars.items():environment["REVETSEC_DURABLE_"+name+"_JAR"]=str(p);environment["REVETSEC_DURABLE_"+name+"_SHA256"]=selected[name][1]
                secrets_dir=instance/"secrets";secrets_dir.mkdir(mode=0o700);environment["REVETSEC_DURABLE_SECRETS"]=str(secrets_dir);environment["REVETSEC_DURABLE_STARTUP"]="fresh"
                # Key generation is a separate JUnit/annotation-free fixture invocation.
                runtime_cp=os.pathsep.join(map(str,[classes,*runtime_jars.values(),home/"lib/servlet-api.jar"]))
                keygen=subprocess.run([str(args.java_home/"bin/java"),"-cp",runtime_cp,"example.DurableIssuerFixture","keygen",str(secrets_dir)],capture_output=True,text=True,env=environment,timeout=15)
                (args.output/"keygen.log").write_text(keygen.stdout+keygen.stderr)
                if keygen.returncode:raise RuntimeError("Owned fixture key preparation failed")
                for p in secrets_dir.iterdir():p.chmod(0o600)
                if docker("image","inspect",image,"--format","{{.Id}}")!=image:raise RuntimeError("Pinned owned PostgreSQL image unavailable")
                envfile=instance/"postgres.env";envfile.write_text("POSTGRES_PASSWORD="+db_password+"\nPOSTGRES_DB=qualification\n");envfile.chmod(0o600)
                with socket.socket()as reservation:reservation.bind(("127.0.0.1",0));db_port=reservation.getsockname()[1]
                docker("network","create","--label","com.revetsec.durable-servlet-issuer=true",network);created.append("network")
                docker("volume","create","--label","com.revetsec.durable-servlet-issuer=true",volume);created.append("volume")
                created.append("container");docker("run","-d","--pull=never","--name",resource,"--network",network,"--label","com.revetsec.durable-servlet-issuer=true","--publish",f"127.0.0.1:{db_port}:5432","--env-file",str(envfile),"--mount",f"type=volume,source={volume},target=/var/lib/postgresql",image)
                for attempt in range(100):
                    ready=subprocess.run(["docker","exec",resource,"psql","-X","-qAt","-U","postgres","-d","qualification","-c","SELECT 1"],capture_output=True,text=True,timeout=2)
                    if ready.returncode==0 and ready.stdout.strip()=="1":break
                    time.sleep(.1)
                else:raise RuntimeError("Owned PostgreSQL startup failed")
                namespace="servlet_issuer";physical=identity("issuer-physical/"+namespace);allocation=identity("issuer-allocation/"+namespace);values=[namespace,physical,identity("issuer-authority/"+namespace),identity("issuer-recovery/"+namespace),identity("issuer-clock/"+namespace)]
                provision="INSERT INTO issuer_store_namespace VALUES("+",".join("'"+v+"'"for v in values)+",0,'"+allocation+"',2,4096,true);\nINSERT INTO issuer_store_escrow VALUES"+",".join("('ISSUER','"+physical+"',"+str(i)+",'"+allocation+"',16,0,0,0)"for i in range(256))+";"
                sql(schema.read_text()+provision)
                sql("CREATE ROLE issuer_runtime LOGIN PASSWORD '"+runtime_password+"'; GRANT CONNECT ON DATABASE qualification TO issuer_runtime;GRANT USAGE ON SCHEMA public TO issuer_runtime;GRANT SELECT ON issuer_store_namespace,issuer_store_root TO issuer_runtime;GRANT INSERT ON issuer_store_root TO issuer_runtime;GRANT SELECT,INSERT,DELETE ON issuer_store_entry TO issuer_runtime;GRANT UPDATE(version,retain_seconds,retain_nanos,sealed_form)ON issuer_store_entry TO issuer_runtime;GRANT SELECT ON issuer_store_escrow TO issuer_runtime;GRANT UPDATE(used_entries,used_bytes)ON issuer_store_escrow TO issuer_runtime;ALTER TABLE issuer_store_entry ENABLE ROW LEVEL SECURITY;CREATE POLICY issuer_select ON issuer_store_entry FOR SELECT TO issuer_runtime USING(true);CREATE POLICY issuer_insert ON issuer_store_entry FOR INSERT TO issuer_runtime WITH CHECK(true);CREATE POLICY issuer_update ON issuer_store_entry FOR UPDATE TO issuer_runtime USING(true)WITH CHECK(true);CREATE POLICY issuer_delete ON issuer_store_entry FOR DELETE TO issuer_runtime USING(kind NOT IN('ISSUER_STATE','SUBJECT_STATE'));")
                environment["REVETSEC_DURABLE_DB_URL"]=f"jdbc:postgresql://127.0.0.1:{db_port}/qualification";environment["REVETSEC_DURABLE_DB_USER"]="issuer_runtime";environment["REVETSEC_DURABLE_DB_PASSWORD"]=runtime_password
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    request_lock = threading.Lock()
                    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.putrequest(method, "/issuer"+path, skip_host=True, skip_accept_encoding=True)
                            connection.putheader("Host", "issuer.example")
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
                        reply=request("GET","/fixture/"+command);assert reply[0]==200,"private-control-"+command;return data(reply)
                    def encoded(fields):return urllib.parse.urlencode(fields).encode("ascii")
                    media=[("Content-Type","application/x-www-form-urlencoded")];origin=[("Origin","https://issuer.example")]
                    def bootstrap():
                        reply=request("POST","/session",b"begin=1",[*media,*origin]);assert reply[0]==200,"synthetic-private-account-bootstrap";return {"cookie":cookie(reply,"__Host-durable-issuer"),"csrf":data(reply)["csrf"]}
                    def issue(browser=None):
                        browser=browser or bootstrap();query=urllib.parse.urlencode({"response_type":"code","client_id":"durable-client","redirect_uri":"https://client.example/cb","resource":"https://resource.example/api","scope":"read","state":"fixture-state","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"})
                        begun=request("GET","/authorize?"+query,headers=[*origin,("Cookie",browser["cookie"]),("X-Fixture-Csrf",browser["csrf"])]);assert begun[0]==200,"genuine-issuer-interaction"
                        approved=request("POST","/approve",encoded({"csrf":browser["csrf"],"interaction":data(begun)["interaction"]}),[*media,*origin,("Cookie",browser["cookie"])])
                        assert approved[0]==303,"genuine-issuer-code";location=urllib.parse.urlsplit(header(approved,"location"));fields=dict(urllib.parse.parse_qsl(location.query,strict_parsing=True));assert location.scheme=="https"and location.netloc=="client.example"and location.path=="/cb"and fields["state"]=="fixture-state","exact-registered-redirect";return fields["code"],browser
                    def redeem(code,verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",extra=(),suffix=b""):return request("POST","/token",encoded({"grant_type":"authorization_code","client_id":"durable-client","redirect_uri":"https://client.example/cb","resource":"https://resource.example/api","code":code,"code_verifier":verifier})+suffix,[*media,*extra])
                    def refresh(token):return request("POST","/token",encoded({"grant_type":"refresh_token","client_id":"durable-client","resource":"https://resource.example/api","refresh_token":token}),media)
                    def protected(token,path="/resource/tenant/alice",extra=()):return request("GET",path,headers=[("Authorization","Bearer "+token),*extra])
                    def introspect(token):return request("POST","/introspect",encoded({"token":token}),[*media,("Authorization","Basic "+base64.b64encode(b"resource:test-only-resource-secret").decode())])
                    def no_output(reply):return reply[0]==503 and not cookies(reply)and not any(k.lower()in["location","www-authenticate"]for k,v in reply[1])and b'access_token'not in reply[2]and b'refresh_token'not in reply[2]and b'protected'not in reply[2]
                    def ready():
                        deadline=time.monotonic()+15
                        while time.monotonic()<deadline:
                            if process.poll()is not None:raise RuntimeError("Owned Tomcat exited")
                            try:
                                if request("GET","/fixture/state")[0]==200:return
                            except(OSError,http.client.HTTPException):pass
                            time.sleep(.05)
                        raise RuntimeError("Owned Tomcat readiness failed")
                    ready();check("actual-selected-artifact-origins",state()["selected_origins"])
                    check("runtime-role-cannot-change-admission-or-capacity",sql("SELECT NOT has_table_privilege('issuer_runtime','issuer_store_namespace','UPDATE')AND NOT has_table_privilege('issuer_runtime','issuer_store_root','DELETE')AND NOT has_table_privilege('issuer_runtime','issuer_store_entry','TRUNCATE')AND NOT has_column_privilege('issuer_runtime','issuer_store_escrow','entry_limit','UPDATE');")=="t")
                    metadata=request("GET","/metadata");public_jwks=request("GET","/jwks");check("actual-issuer-metadata-and-jwks-http",metadata[0]==200 and data(metadata)["issuer"]=="https://issuer.example/issuer"and public_jwks[0]==200 and len(data(public_jwks)["keys"])==1 and data(public_jwks)["keys"][0]["kid"]=="fixture")
                    initial=snapshot("initial-root-subject");check("actual-initial-root-subject-and256quota",initial["counts"]["ISSUER_STATE"]==1 and initial["counts"]["SUBJECT_STATE"]==1)
                    check("get-does-not-bootstrap",data(request("GET","/session"))["current"]is False and state()["sessions"]==0)
                    check("fixture-gate",request("GET","/fixture/state",authenticated=False)[0]==401)
                    check("wrong-origin-before-db",request("POST","/session",b"begin=1",[*media,("Origin","https://wrong.invalid")])[0]==403)
                    before=state();check("complete-body-plus-one-before-allocation",request("POST","/session",b'a'*129,[*media,*origin])[0]==413 and state()["sessions"]==before["sessions"] and state()["connections"]==before["connections"])
                    check("chunked-body-plus-one-before-allocation",request("POST","/session",b'a'*129,[*media,*origin],chunked=True)[0]==413 and state()["sessions"]==before["sessions"])
                    check("raw-media-multiplicity-before-allocation",request("POST","/session",b"begin=1",[*media,*media,*origin])[0]==400 and state()["sessions"]==before["sessions"])
                    # Keep sending small chunks; progress must not renew the original request deadline.
                    started=time.monotonic();received=b"";slow=socket.create_connection(("127.0.0.1",port),timeout=2)
                    try:
                        slow.sendall(("POST /issuer/session HTTP/1.1\r\nHost: issuer.example\r\nX-Fixture-Credential: "+credential+"\r\nOrigin: https://issuer.example\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode())
                        while time.monotonic()-started<7:
                            slow.sendall(b"1\r\na\r\n")
                            readable,_,_=select.select([slow],[],[],.1)
                            if readable:
                                received=slow.recv(4096)
                                if received:break
                    finally:slow.close()
                    elapsed=time.monotonic()-started;status=received.split(b" ",2)[1]if received.startswith(b"HTTP/1.1 ")else b""
                    check("slow-progress-original-request-deadline",status==b"503"and 3.5<=elapsed<6.5 and state()["sessions"]==before["sessions"] and state()["connections"]==before["connections"],{"status":status.decode("ascii",errors="replace"),"elapsedSeconds":round(elapsed,3)})
                    browser=bootstrap();before=state();control("admission-deny");check("application-admission-before-expensive-work",request("POST","/session",b"begin=1",[*media,*origin])[0]==503 and state()["connections"]==before["connections"]);control("admission-allow")
                    code,browser=issue(browser);before=snapshot("before-pkce-negative");reply=redeem(code,"A"*43);check("wrong-pkce-no-token",reply[0]==400);check("wrong-pkce-no-store-effect",snapshot("after-pkce-negative")["stateSha256"]==before["stateSha256"])
                    counters=state();before_ambiguity=snapshot("before-raw-token-ambiguity")
                    check("raw-token-duplicate-field-before-store",redeem(code,suffix=b"&code=ignored")[0]==400 and state()["connections"]==counters["connections"])
                    check("raw-token-duplicate-media-before-store",redeem(code,extra=media)[0]==400 and state()["connections"]==counters["connections"])
                    bare=request("POST","/token?",encoded({"grant_type":"authorization_code","client_id":"durable-client","redirect_uri":"https://client.example/cb","resource":"https://resource.example/api","code":code,"code_verifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}),media)
                    check("tomcat-bare-query-refused-before-store",bare[0]==400 and state()["connections"]==counters["connections"])
                    check("raw-token-refusals-no-data-version-quota-change",snapshot("after-raw-token-ambiguity")["stateSha256"]==before_ambiguity["stateSha256"])
                    reply=redeem(code);check("genuine-http-code-exchange",reply[0]==200,reply[0]);pair=data(reply);access=pair["access_token"];rotation=pair["refresh_token"]
                    check("real-status-backed-protected-access",protected(access)[0]==200 and data(introspect(access))["active"]is True)
                    check("current-tenant-and-object-denied",protected(access,"/resource/other/alice")[0]==403 and protected(access,"/resource/tenant/bob")[0]==403)
                    check("raw-duplicate-bearer-denied",protected(access,extra=[("Authorization","Bearer "+access)])[0]==400)
                    check("ambient-cookie-refused",protected(access,extra=[("Cookie",browser["cookie"])])[0]==400)
                    check("query-bearer-refused",protected(access,"/resource/tenant/alice?access_token=ignored")[0]==400)
                    control("deny");check("current-account-policy-denied",protected(access)[0]==403);control("allow")
                    before=snapshot("before-authority-outage");control("authority-unavailable");reply=protected(access);check("authority-outage-not-invalid-token",no_output(reply),reply[0]);control("authority-healthy");check("authority-outage-no-write",snapshot("after-authority-outage")["stateSha256"]==before["stateSha256"])
                    check("healthy-authority-new-request",protected(access)[0]==200)
                    reply=refresh(rotation);check("genuine-refresh-rotates",reply[0]==200 and data(reply)["refresh_token"]!=rotation);pair=data(reply);access=pair["access_token"];rotation=pair["refresh_token"]
                    replay_code,replay_browser=issue();replay_control=redeem(replay_code);assert replay_control[0]==200,"code-replay-control-issued";replay_access=data(replay_control)["access_token"];before_replay=snapshot("before-live-code-replay");replayed=redeem(replay_code)
                    check("valid-code-replay-refuses-and-revokes",replayed[0]==400 and protected(replay_access)[0]==401)
                    check("credential-rejection-can-carry-real-revocation",snapshot("after-live-code-replay")["stateSha256"]!=before_replay["stateSha256"])
                    revoked_code,revoked_browser=issue();revoked_reply=redeem(revoked_code);assert revoked_reply[0]==200,"revocation-control-issued";revoked_pair=data(revoked_reply)
                    revoked=request("POST","/revoke",encoded({"token":revoked_pair["refresh_token"],"client_id":"durable-client"}),media)
                    check("actual-http-revocation-persists-status",revoked[0]==200 and protected(revoked_pair["access_token"])[0]==401 and data(introspect(revoked_pair["access_token"]))["active"]is False)
                    before=snapshot("before-browser-close");closed=request("POST","/logout",encoded({"csrf":browser["csrf"]}),[*media,*origin,("Cookie",browser["cookie"])]);check("local-browser-close-separate-from-grant",closed[0]==204 and data(request("GET","/session",headers=[("Cookie",browser["cookie"])]))["current"]is False and protected(access)[0]==200);check("browser-close-no-issuer-mutation",snapshot("after-browser-close")["stateSha256"]==before["stateSha256"])
                    for mode,applied in[("unknown-before",False),("unknown-after",True),("known-after",True)]:
                        uncertain,b=issue();before=snapshot("before-"+mode);counters=state();control(mode);reply=redeem(uncertain);after=snapshot("after-"+mode);observed=state();check("no-credential-output-"+mode,no_output(reply),reply[0]);check("one-commit-attempt-no-auto-retry-"+mode,observed["commit_attempts"]==counters["commit_attempts"]+1)
                        check("actual-effect-"+mode,(after["stateSha256"]!=before["stateSha256"])is applied and after["counts"]["ACCESS_TOKEN"]==before["counts"]["ACCESS_TOKEN"]+(1 if applied else 0))
                        if mode.startswith("unknown"):check("unknown-is-distinct-"+mode,observed["unknown_failures"]==counters["unknown_failures"]+1 and observed["known_failures"]==counters["known_failures"])
                        else:check("known-committed-withheld-distinct",observed["known_failures"]==counters["known_failures"]+1 and observed["unknown_failures"]==counters["unknown_failures"]);control("authority-healthy")
                    limited,b=issue();sql("BEGIN;"+admission_lock()+"UPDATE issuer_store_escrow SET entry_limit=used_entries WHERE namespace='"+physical+"';COMMIT;");before=snapshot("before-capacity-refusal");reply=redeem(limited)
                    check("allocated-capacity-refuses-without-output",no_output(reply),reply[0]);check("capacity-refusal-no-data-version-quota-mutation",snapshot("after-capacity-refusal")["stateSha256"]==before["stateSha256"])
                    sql("BEGIN;"+admission_lock()+"UPDATE issuer_store_escrow SET entry_limit=16 WHERE namespace='"+physical+"';COMMIT;")
                    signing,b=issue();before=snapshot("before-key-outage");control("keys-unavailable");reply=redeem(signing);check("actual-key-provider-outage-no-token",no_output(reply),reply[0]);check("key-outage-no-data-version-quota-mutation",snapshot("after-key-outage")["stateSha256"]==before["stateSha256"]);control("keys-healthy")
                    unused,b=issue();before=snapshot("before-no-callback");counters=state();control("open-unavailable");reply=redeem(unused);check("unavailable-before-callback-no-output",no_output(reply),reply[0]);observed=state();check("sustained-open-refusals-without-commit",observed["open_refusals"]>counters["open_refusals"]and observed["commit_attempts"]==counters["commit_attempts"]);check("unavailable-before-callback-no-effect",snapshot("after-no-callback")["stateSha256"]==before["stateSha256"]);control("connections-healthy")
                    # A genuine active grant and persistent keys survive actual Tomcat/JVM restart;
                    # application browser sessions in this selected profile are deliberately volatile.
                    active_code,browser=issue();active_reply=redeem(active_code);assert active_reply[0]==200,"restart-control-issued";kept=data(active_reply);before=snapshot("before-tomcat-restart");process.terminate();process.wait(timeout=5);receipt["serverPhases"].append({"phase":"fresh","stopped":True})
                    environment["REVETSEC_DURABLE_STARTUP"]="established"
                    process=subprocess.Popen([str(args.java_home/"bin/java"),"-Djava.awt.headless=true","-Dcatalina.home="+str(home),"-Dcatalina.base="+str(base),"-cp",os.pathsep.join(map(str,[home/"bin/bootstrap.jar",home/"bin/tomcat-juli.jar"])),"org.apache.catalina.startup.Bootstrap","start"],stdout=runtime,stderr=runtime,env=environment);ready()
                    check("persistent-key-publishes-same-jwks-after-restart",request("GET","/jwks")[2]==public_jwks[2])
                    check("actual-restarted-jvm-no-lazy-initialization",snapshot("after-tomcat-restart")["stateSha256"]==before["stateSha256"])
                    check("restart-persists-issuer-status-not-volatile-browser",protected(kept["access_token"])[0]==200 and data(request("GET","/session",headers=[("Cookie",browser["cookie"])]))["current"]is False)
                    check("restart-refresh-from-persisted-grant",refresh(kept["refresh_token"])[0]==200)
                    before=snapshot("before-owned-db-restart");docker("restart",resource)
                    for attempt in range(100):
                        resumed=subprocess.run(["docker","exec",resource,"psql","-X","-qAt","-U","postgres","-d","qualification","-c","SELECT 1"],capture_output=True,text=True,timeout=2)
                        if resumed.returncode==0 and resumed.stdout.strip()=="1":break
                        time.sleep(.1)
                    else:raise RuntimeError("Owned PostgreSQL restart failed")
                    check("owned-postgres-restart-preserves-data-and256quota",snapshot("after-owned-db-restart")["stateSha256"]==before["stateSha256"]and protected(kept["access_token"])[0]==200)
                    control("revoke-subject");check("durable-subject-fence-denies-old-grant",protected(kept["access_token"])[0]==401)
                    epoch_code,epoch_browser=issue();epoch_reply=redeem(epoch_code);assert epoch_reply[0]==200,"new-subject-generation-control";epoch_pair=data(epoch_reply)
                    control("revoke-issuer");check("durable-issuer-fence-denies-old-grant",protected(epoch_pair["access_token"])[0]==401)
                    fresh_code,fresh_browser=issue();fresh_reply=redeem(fresh_code);assert fresh_reply[0]==200,"new-issuer-generation-control";kept=data(fresh_reply)
                    # Close admission while holding the exact reference-store exclusive lock.
                    before=snapshot("before-admission-close");sql("BEGIN;"+admission_lock()+"UPDATE issuer_store_namespace SET admission_open=false WHERE namespace='servlet_issuer';COMMIT;")
                    check("closed-admission-denies-old-worker-protected-access",no_output(protected(kept["access_token"])))
                    check("closed-admission-no-protocol-write",snapshot("after-admission-close")["stateSha256"]==before["stateSha256"])
                    # Reopening with a different recovery generation cannot authorize the retained
                    # old process/authority tuple or recreate a missing root automatically.
                    new_recovery=identity("issuer-recovery/new-generation")
                    sql("BEGIN;"+admission_lock()+"UPDATE issuer_store_namespace SET recovery_generation='"+new_recovery+"',admission_open=true WHERE namespace='servlet_issuer';COMMIT;")
                    check("recovery-generation-fences-old-worker",no_output(protected(kept["access_token"])))
                    check("recovery-fence-no-status-rescue-or-mutation",snapshot("after-recovery-generation")["stateSha256"]==before["stateSha256"])
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
        cleanup=[]
        for kind,name,command in[("container",resource,["rm","-f",resource]),("volume",volume,["volume","rm",volume]),("network",network,["network","rm",network])]:
            if kind in created:
                completed=subprocess.run(["docker",*command],capture_output=True,text=True,timeout=20);cleanup.append(completed.returncode==0)
        receipt["ownedDatabaseRemoved"]=all(cleanup)and len(cleanup)==len(created);receipt["databaseCleanup"]=dict(zip(reversed(created),cleanup))
        if not receipt["ownedDatabaseRemoved"]:receipt["success"]=False
        if not receipt["ownedProcessStopped"] or not receipt["ownedInstanceRemoved"]: receipt["success"] = False
        (args.output/"RESULT.json").write_text(json.dumps(receipt, indent=2)+"\n")
    print(json.dumps({"success":receipt["success"], "checks":len(receipt["checks"]),
                      "failure":receipt.get("failure"), "ownedProcessStopped":receipt["ownedProcessStopped"],
                      "ownedInstanceRemoved":receipt["ownedInstanceRemoved"]}))
    return 0 if receipt["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
