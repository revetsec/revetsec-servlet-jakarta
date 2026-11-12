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

"""Qualify actual paired Servlet typed passkey HTTP composition with owned disposable PostgreSQL."""
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
    parser.add_argument("--application-source",type=Path)
    parser.add_argument("--scenario",choices=["main","unknown-before","unknown-after","known-after","worker-forward"],default="main")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parent.parent
    namespace = "jakarta" if repo.name.endswith("jakarta") else "javax"
    pins_path = repo/"verification/m12-container/runtime.json"
    pins = json.loads(pins_path.read_text())
    recipes=[args.durable_recipe_source or repo/"docs/ServletDurableBackendRecipe.java",args.workflow_source or repo/"docs/ServletWorkflowRecipes.java",args.application_source or repo/"docs/ServletPasskeyActionsRecipe.java"]
    pg=args.reference_store_source_root or repo.parent/"revetsec/examples/postgresql-pending-store"
    schema=pg/"webauthn-schema.sql"
    store_sources=sorted((pg/"src/main/java").rglob("*.java"))
    required_store_sources=[pg/"src/main/java/example/pending"/name for name in ["PostgresqlWebAuthnStore.java","WebAuthnPgScope.java","WebAuthnPgLocks.java","WebAuthnPgCapacity.java","WebAuthnPgTransactions.java"]]
    image="sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a"
    annotations = [args.annotations_repository/"org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
                   args.annotations_repository/"com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
                   args.annotations_repository/"com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]
    new_sources=[args.servlet_source or fixture/"DurablePasskeyServlet.java",args.fixture_source or fixture/"DurablePasskeyFixture.java"]
    bridge=pg/"src/test/java/com/revetsec/webauthn/WebAuthnFixtureWorker.java"
    sources=[*recipes,*new_sources,bridge]
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
               "coreJarSha256":args.core_sha256,"adapterJarSha256":args.adapter_sha256,"selectedArtifacts":{n:{"path":str(p),"sha256":h}for n,(p,h)in selected.items()},"sourceInputs":inputs,"postgresImage":image,"ownedDatabaseRemoved":False,"databaseSnapshots":[],"serverPhases":[],"scenario":args.scenario, "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Actual selected typed-passkey/Servlet/reference-store HTTP composition with private synthetic keys/account, scripted authority, existing test-only worker clock bridge and owned PostgreSQL; no UTC/fullC/fleet/physical/browser/TLS/deployment/finalRC proof"}
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
        physical=identity("webauthn-physical/servlet_webauthn").encode();value=hashlib.sha256(b"revetsec/pg-admission/v1\0"+struct.pack("!I",8)+b"WEBAUTHN"+struct.pack("!I",len(physical))+physical).digest();first,second=struct.unpack("!ii",value[:8]);return "SELECT pg_advisory_xact_lock("+str(first)+","+str(second)+");"
    def snapshot(label):
        raw=sql("SELECT coalesce(json_agg(row_to_json(x)ORDER BY storage_key),'[]')FROM(SELECT storage_key,kind,version,sealed_size,expires_seconds,expires_nanos,encode(sha256(convert_to(sealed_form,'UTF8')),'hex') AS form_sha256 FROM webauthn_store_entry WHERE namespace='servlet_webauthn')x;")
        rows=json.loads(raw);quotas=json.loads(sql("SELECT json_agg(row_to_json(x)ORDER BY bucket) FROM(SELECT bucket,allocation_generation,entry_limit,used_entries,used_bytes,byte_limit FROM webauthn_store_escrow WHERE namespace='"+identity("webauthn-physical/servlet_webauthn")+"')x;"));assert len(quotas)==256,"all256escrows-observed"
        counts={kind:sum(r["kind"]==kind for r in rows)for kind in ["CEREMONY","CREDENTIAL","ACCOUNT_CREDENTIAL_INDEX","ACCOUNT_FENCE","NAMESPACE_CLOCK"]};usage=[0]*256
        for row in rows:usage[hashlib.sha256(row["storage_key"].encode()).digest()[0]]+=1
        assert all(q["used_entries"]==usage[q["bucket"]]and q["used_bytes"]==0 for q in quotas),"independent-all256quota-accounting"
        value={"label":label,"sequenceLastValue":int(sql("SELECT last_value FROM webauthn_store_version_seq;")),"rows":rows,"quotas":quotas,"counts":counts,"stateSha256":hashlib.sha256((raw+json.dumps(quotas,sort_keys=True)).encode()).hexdigest()};receipt["databaseSnapshots"].append(value);return value
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-durable-webauthn-"+namespace+"-") as directory:
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
                    '<web-app><servlet><servlet-name>issuer</servlet-name><servlet-class>example.DurablePasskeyServlet</servlet-class>'
                    '<load-on-startup>1</load-on-startup></servlet><servlet-mapping><servlet-name>issuer</servlet-name>'
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
                credential=secrets.token_urlsafe(32);environment=dict(os.environ);environment.pop("JAVA_TOOL_OPTIONS",None);environment.pop("JDK_JAVA_OPTIONS",None)
                environment["REVETSEC_DURABLE_FIXTURE_CREDENTIAL"]=credential
                for name,p in runtime_jars.items():environment["REVETSEC_DURABLE_"+name+"_JAR"]=str(p);environment["REVETSEC_DURABLE_"+name+"_SHA256"]=selected[name][1]
                secrets_dir=instance/"secrets";secrets_dir.mkdir(mode=0o700);environment["REVETSEC_DURABLE_SECRETS"]=str(secrets_dir);environment["REVETSEC_DURABLE_STARTUP"]="fresh"
                environment["REVETSEC_TEST_WA_WORKER_NOW"]=str(1793880000+(6 if args.scenario=="worker-forward"else 0));environment["REVETSEC_TEST_WA_AUTHORITY_NOW"]="1793880000"
                # Key generation is a separate JUnit/annotation-free fixture invocation.
                runtime_cp=os.pathsep.join(map(str,[classes,*runtime_jars.values(),home/"lib/servlet-api.jar"]))
                keygen=subprocess.run([str(args.java_home/"bin/java"),"-cp",runtime_cp,"example.DurablePasskeyFixture","keygen",str(secrets_dir)],capture_output=True,text=True,env=environment,timeout=15)
                (args.output/"keygen.log").write_text(keygen.stdout+keygen.stderr)
                if keygen.returncode:raise RuntimeError("Owned fixture key preparation failed")
                for p in secrets_dir.iterdir():p.chmod(0o600)
                sealer_digest=base64.urlsafe_b64encode(hashlib.sha256(base64.b64decode((secrets_dir/"sealer.txt").read_bytes())).digest()).decode().rstrip("=");epoch=identity("webauthn-epoch/servlet_webauthn");(secrets_dir/"marker.txt").write_text(epoch+"\n"+sealer_digest+"\n");(secrets_dir/"marker.txt").chmod(0o600)
                environment["REVETSEC_DURABLE_SEALER_DIGEST"]=sealer_digest;environment["REVETSEC_DURABLE_EXPECTED_EPOCH"]=epoch
                key_fingerprints={p.name:digest(p)for p in secrets_dir.iterdir()if p.suffix==".der"or p.name=="sealer.txt"};receipt["persistentKeyFingerprints"]=key_fingerprints
                if docker("image","inspect",image,"--format","{{.Id}}")!=image:raise RuntimeError("Pinned owned PostgreSQL image unavailable")
                envfile=instance/"postgres.env";envfile.write_text("POSTGRES_PASSWORD="+db_password+"\nPOSTGRES_DB=qualification\n");envfile.chmod(0o600)
                with socket.socket()as reservation:reservation.bind(("127.0.0.1",0));db_port=reservation.getsockname()[1]
                docker("network","create","--label","com.revetsec.durable-servlet-issuer=true",network);created.append("network")
                docker("volume","create","--label","com.revetsec.durable-servlet-issuer=true",volume);created.append("volume")
                created.append("container");docker("run","-d","--pull=never","--name",resource,"--network",network,"--label","com.revetsec.durable-servlet-issuer=true","--publish",f"127.0.0.1:{db_port}:5432","--env-file",str(envfile),"--mount",f"type=volume,source={volume},target=/var/lib/postgresql",image)
                for attempt in range(100):
                    ready=subprocess.run(["docker","exec",resource,"psql","-h","127.0.0.1","-X","-qAt","-U","postgres","-d","qualification","-c","SELECT 1"],capture_output=True,text=True,timeout=2)
                    if ready.returncode==0 and ready.stdout.strip()=="1":break
                    time.sleep(.1)
                else:raise RuntimeError("Owned PostgreSQL startup failed")
                namespace="servlet_webauthn";physical=identity("webauthn-physical/"+namespace);allocation=identity("webauthn-allocation/"+namespace);values=[namespace,physical,identity("webauthn-authority/"+namespace),identity("webauthn-recovery/"+namespace),identity("webauthn-clock/"+namespace)]
                provision="INSERT INTO webauthn_store_namespace VALUES("+",".join("'"+v+"'"for v in values)+",0,'"+allocation+"',2,4096,true);\nINSERT INTO webauthn_store_escrow VALUES"+",".join("('WEBAUTHN','"+physical+"',"+str(i)+",'"+allocation+"',16,0,0,0)"for i in range(256))+";"
                sql(schema.read_text()+provision+"INSERT INTO webauthn_recovery_epoch VALUES('servlet_webauthn','"+epoch+"','"+sealer_digest+"');")
                sql("CREATE ROLE webauthn_runtime LOGIN PASSWORD '"+runtime_password+"'; GRANT CONNECT ON DATABASE qualification TO webauthn_runtime;GRANT USAGE ON SCHEMA public TO webauthn_runtime;GRANT SELECT ON webauthn_store_namespace,webauthn_store_root,webauthn_recovery_epoch TO webauthn_runtime;GRANT INSERT ON webauthn_store_root TO webauthn_runtime;GRANT SELECT,INSERT,DELETE ON webauthn_store_entry TO webauthn_runtime;GRANT UPDATE(kind,version,sealed_size,expires_seconds,expires_nanos,sealed_form)ON webauthn_store_entry TO webauthn_runtime;GRANT SELECT ON webauthn_store_escrow TO webauthn_runtime;GRANT UPDATE(used_entries,used_bytes)ON webauthn_store_escrow TO webauthn_runtime;GRANT USAGE ON SEQUENCE webauthn_store_version_seq TO webauthn_runtime;ALTER TABLE webauthn_store_entry ENABLE ROW LEVEL SECURITY;CREATE POLICY webauthn_select ON webauthn_store_entry FOR SELECT TO webauthn_runtime USING(true);CREATE POLICY webauthn_insert ON webauthn_store_entry FOR INSERT TO webauthn_runtime WITH CHECK(true);CREATE POLICY webauthn_update ON webauthn_store_entry FOR UPDATE TO webauthn_runtime USING(true)WITH CHECK(true);CREATE POLICY webauthn_delete ON webauthn_store_entry FOR DELETE TO webauthn_runtime USING(kind='CEREMONY');")
                environment["REVETSEC_DURABLE_DB_URL"]=f"jdbc:postgresql://127.0.0.1:{db_port}/qualification";environment["REVETSEC_DURABLE_DB_USER"]="webauthn_runtime";environment["REVETSEC_DURABLE_DB_PASSWORD"]=runtime_password
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
                        reply=request("GET","/fixture/"+command);assert reply[0]==200,"private-control-"+command;return data(reply)
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
                    def grants():return state()["application"]["sessions"]["grants"]
                    def ready():
                        deadline=time.monotonic()+15
                        while time.monotonic()<deadline:
                            if process.poll()is not None:raise RuntimeError("Owned Tomcat stopped before ready")
                            try:
                                if request("GET","/fixture/state")[0]==200:return
                            except(OSError,http.client.HTTPException):pass
                            time.sleep(.05)
                        raise RuntimeError("Owned Tomcat readiness failed")
                    def no_grant(reply):return reply[0]in[400,403,503]and grants()==0
                    ready();check("selected-artifact-origins-runtime",state()["origins_verified"],state()["java_version"])
                    check("fixture-credential-required",request("GET","/fixture/state",authenticated=False)[0]==401)
                    check("runtime-role-bounded",sql("SELECT NOT has_table_privilege('webauthn_runtime','webauthn_store_namespace','UPDATE')AND NOT has_table_privilege('webauthn_runtime','webauthn_recovery_epoch','UPDATE')AND NOT has_table_privilege('webauthn_runtime','webauthn_store_root','DELETE')AND NOT has_table_privilege('webauthn_runtime','webauthn_store_entry','TRUNCATE')AND NOT has_column_privilege('webauthn_runtime','webauthn_store_escrow','entry_limit','UPDATE');")=="t")
                    initial=snapshot("initial-empty");check("all256quotas-zero-no-implicit-root",not initial["rows"]and all(q["used_entries"]==0 for q in initial["quotas"]))
                    check("get-no-session-allocation",data(request("GET","/session"))["authenticated"]is False and state()["application"]["sessions"]["sessions"]==0)
                    browser=login()
                    if args.scenario=="worker-forward":
                        before=snapshot("before-worker-displacement");reply=request("POST","/register/start",headers=fields(browser,True));check("scripted-worker-displacement-refuses-no-fallback",reply[0]==503 and grants()==0,reply[0]);check("worker-clock-refusal-no-data-version-quota-change",snapshot("after-worker-displacement")["stateSha256"]==before["stateSha256"])
                    else:
                        one=register(browser,"one");two=register(browser,"two");check("actual-pg-two-key-registration",one!=two and set(data(request("POST","/credentials/list",headers=fields(browser)))["credentialIds"])=={one,two})
                        established=snapshot("after-real-registration");check("root-index-fence-and-credentials-in-pg",established["counts"]["NAMESPACE_CLOCK"]==1 and established["counts"]["ACCOUNT_FENCE"]==1 and established["counts"]["ACCOUNT_CREDENTIAL_INDEX"]==1 and established["counts"]["CREDENTIAL"]==2)
                        anonymous=bootstrap();prepared=options(anonymous,"/sign-in/start");reply=finish(anonymous,"/sign-in/finish",prepared);check("genuine-pg-sign-in-rotates-session",reply[0]==200 and cookie(reply,"__Host-passkey-actions")!=anonymous["cookie"]);browser={"cookie":cookie(reply,"__Host-passkey-actions"),"csrf":data(reply)["csrf"]}
                        if args.scenario!="main":
                            prepared=reauth(browser);before=snapshot("before-"+args.scenario);counters=state();control(args.scenario);reply=approved(browser,prepared);after=snapshot("after-"+args.scenario);observed=state()
                            check("jdbc-outcome-withholds-local-grant-"+args.scenario,reply[0]==503 and grants()==0 and observed["application"]["admission_open"]is False,reply[0])
                            check("one-actual-mutation-commit-no-retry",observed["commit_attempts"]==counters["commit_attempts"]+1)
                            check("factual-sql-effect-"+args.scenario,(after["stateSha256"]==before["stateSha256"])==(args.scenario=="unknown-before"))
                            check("confirmed-vs-unknown-provenance",observed["unknown_faults"]-counters["unknown_faults"]==(0 if args.scenario=="known-after"else 1)and observed["known_faults"]-counters["known_faults"]==(1 if args.scenario=="known-after"else 0))
                            check("actual-commit-effect-counter",observed["actual_applied_commits"]-counters["actual_applied_commits"]==(0 if args.scenario=="unknown-before"else 1))
                            check("closed-app-no-status-rescue-or-retry",sensitive(browser)[0]==503 and state()["commit_attempts"]==observed["commit_attempts"]and snapshot("after-closed-admission")["stateSha256"]==after["stateSha256"])
                        else:
                            before=snapshot("before-raw-carriers");counters=state()
                            for name,path,extra in[("bare-query","/reauth/start?",[]),("duplicate-csrf","/reauth/start",[("X-CSRF-Token",browser["csrf"])]),("duplicate-cookie","/reauth/start",[("Cookie",browser["cookie"])]),("bearer","/reauth/start",[("Authorization","Bearer untrusted")])]:
                                check("raw-carrier-before-rp-"+name,request("POST",path,headers=fields(browser,False,extra))[0]==400 and state()["commit_attempts"]==counters["commit_attempts"]and state()["connections"]==counters["connections"])
                            check("raw-carrier-data-version-all256quota-unchanged",snapshot("after-raw-carriers")["stateSha256"]==before["stateSha256"])
                            counters=state();control("gate-deny");reply=request("POST","/reauth/start",headers=fields(browser));check("host-admission-refuses-before-connection-keywork",reply[0]==503 and state()["connections"]==counters["connections"]);control("gate-allow")
                            step=reauth(browser);before=snapshot("before-bounded-body");counters=state();reply=request("POST","/reauth/finish",b"x"*65537,fields(browser,False,[*json_media,("X-Ceremony-Id",step["ceremonyId"])]),chunked=True);check("stream-plus-one-before-rp-mutation",reply[0]==400 and state()["connections"]>counters["connections"]and state()["commit_attempts"]==counters["commit_attempts"]and snapshot("after-bounded-body")["stateSha256"]==before["stateSha256"])
                            check("bounded-body-refusal-retains-original-genuine-pending",approved(browser,step)[0]==200 and sensitive(browser)[0]==200)
                            step=reauth(browser);assert approved(browser,step)[0]==200;check("typed-pg-proof-one-local-action",sensitive(browser)[0]==200 and sensitive(browser)[0]==403)
                            step=reauth(browser,"/credentials/self-remove/start",two);assert finish(browser,"/credentials/self-remove/finish",step,"one")[0]==200
                            before=snapshot("before-self-removal");removed=request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",two)]));after=snapshot("after-self-removal");check("other-authenticating-key-removes-exact-target-once",removed[0]==200 and request("POST","/credentials/self-remove",headers=fields(browser,False,[("X-Credential-Id",two)]))[0]==403 and data(request("POST","/credentials/list",headers=fields(browser)))["credentialIds"]==[one])
                            check("removed-credential-tombstone-retained",before["stateSha256"]!=after["stateSha256"]and after["counts"]["CREDENTIAL"]==2)
                            before=snapshot("before-authority-outage");control("authority-unavailable");reply=request("POST","/reauth/start",headers=fields(browser));check("authority-unavailable-no-proof-or-grant",no_grant(reply),reply[0]);check("authority-refusal-no-data-version-quota-change",snapshot("after-authority-outage")["stateSha256"]==before["stateSha256"]);control("authority-healthy")
                            before=snapshot("before-open-refusal");counters=state();control("open-unavailable");reply=request("POST","/reauth/start",headers=fields(browser));observed=state();check("sustained-connection-refusal-before-commit",reply[0]==503 and observed["open_refusals"]>counters["open_refusals"]and observed["commit_attempts"]==counters["commit_attempts"]);control("connections-healthy");check("connection-refusal-no-data-version-quota-change",snapshot("after-open-refusal")["stateSha256"]==before["stateSha256"])
                            sql("BEGIN;"+admission_lock()+"UPDATE webauthn_store_escrow SET entry_limit=used_entries WHERE namespace='"+physical+"';COMMIT;");before=snapshot("before-capacity-refusal");reply=request("POST","/reauth/start",headers=fields(browser));check("all256allocated-capacity-refusal",no_grant(reply),reply[0]);check("capacity-no-data-version-quota-change",snapshot("after-capacity-refusal")["stateSha256"]==before["stateSha256"]);sql("BEGIN;"+admission_lock()+"UPDATE webauthn_store_escrow SET entry_limit=16 WHERE namespace='"+physical+"';COMMIT;")
                            # Normal restart only: never reopen an uncertain/reconciliation-closed host.
                            other=login();assert approved(other)[0]==200;oldpending=reauth(browser);before=snapshot("before-tomcat-restart");oldbrowser=browser;process.terminate();process.wait(timeout=5);receipt["serverPhases"].append({"phase":"normal-initial","stopped":True})
                            assert all(digest(secrets_dir/name)==h for name,h in key_fingerprints.items()),"persistent-key-material-changed"
                            process=subprocess.Popen([str(args.java_home/"bin/java"),"-Djava.awt.headless=true","-Dcatalina.home="+str(home),"-Dcatalina.base="+str(base),"-cp",os.pathsep.join(map(str,[home/"bin/bootstrap.jar",home/"bin/tomcat-juli.jar"])),"org.apache.catalina.startup.Bootstrap","start"],stdout=runtime,stderr=runtime,env=environment);ready()
                            check("actual-jvm-restart-preserves-keys-data-all256quota",all(digest(secrets_dir/name)==h for name,h in key_fingerprints.items())and snapshot("after-tomcat-restart")["stateSha256"]==before["stateSha256"])
                            check("jvm-restart-loses-volatile-browser-and-grants",data(request("GET","/session",headers=[("Cookie",oldbrowser["cookie"])]))["authenticated"]is False and grants()==0)
                            anonymous=bootstrap();prepared=options(anonymous,"/sign-in/start");reply=finish(anonymous,"/sign-in/finish",prepared);check("persisted-key-and-credential-genuine-restarted-sign-in",reply[0]==200,reply[0]);browser={"cookie":cookie(reply,"__Host-passkey-actions"),"csrf":data(reply)["csrf"]}
                            before=snapshot("before-old-pending-reuse");reply=finish(browser,"/reauth/finish",oldpending);check("restart-does-not-transfer-old-pending-or-proof",reply[0]==403 and grants()==0 and snapshot("after-old-pending-reuse")["stateSha256"]==before["stateSha256"])
                            before=snapshot("before-postgres-restart");docker("restart",resource)
                            for unused in range(100):
                                try:
                                    if sql("SELECT 1")=="1":break
                                except RuntimeError:pass
                                time.sleep(.1)
                            else:raise RuntimeError("Owned PostgreSQL restart failed")
                            check("actual-postgres-restart-data-all256quotas",snapshot("after-postgres-restart")["stateSha256"]==before["stateSha256"]and data(request("POST","/credentials/list",headers=fields(browser)))["credentialIds"]==[one])
                            step=reauth(browser);control("pause-after")
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
                                pending=pool.submit(approved,browser,step);until=time.monotonic()+2
                                while not state()["commit_paused"]and time.monotonic()<until:time.sleep(.01)
                                check("actual-commit-held-inside-operation-gate",state()["commit_paused"])
                                import fcntl
                                with(secrets_dir/"gate.lock").open("r+b")as barrier:
                                    blocked=False
                                    try:fcntl.lockf(barrier,fcntl.LOCK_EX|fcntl.LOCK_NB)
                                    except BlockingIOError:blocked=True
                                    if not blocked:fcntl.lockf(barrier,fcntl.LOCK_UN)
                                check("controller-exclusive-barrier-refuses-active-writer",blocked)
                                control("release");reply=pending.result(timeout=5)
                            check("known-commit-completes-after-bounded-release",reply[0]==200 and sensitive(browser)[0]==200)
                            step=reauth(browser);assert approved(browser,step)[0]==200;before=snapshot("before-controller-fence")
                            with(secrets_dir/"gate.lock").open("r+b")as barrier:
                                fcntl.lockf(barrier,fcntl.LOCK_EX|fcntl.LOCK_NB);sql("BEGIN;"+admission_lock()+"UPDATE webauthn_store_namespace SET admission_open=false WHERE namespace='servlet_webauthn';COMMIT;");new_epoch=identity("webauthn-epoch/new");new_recovery=identity("webauthn-recovery/new");sql("BEGIN;"+admission_lock()+"UPDATE webauthn_recovery_epoch SET epoch='"+new_epoch+"'WHERE namespace='servlet_webauthn';UPDATE webauthn_store_namespace SET recovery_generation='"+new_recovery+"',admission_open=true WHERE namespace='servlet_webauthn';COMMIT;");(secrets_dir/"marker.txt").write_text(new_epoch+"\n"+sealer_digest+"\n");fcntl.lockf(barrier,fcntl.LOCK_UN)
                            check("changed-external-marker-fences-retained-action-grant",sensitive(browser)[0]==503)
                            check("changed-recovery-fences-retained-rp",request("POST","/reauth/start",headers=fields(browser))[0]==503)
                            check("fencing-no-data-version-quota-mutation",snapshot("after-controller-fence")["stateSha256"]==before["stateSha256"])
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
