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
import ssl
import base64
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
    parser.add_argument("--chrome",type=Path,required=True)
    parser.add_argument("--node",type=Path,required=True)
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
    browser_source=fixture/"browser-check.mjs"
    auditor = repo/"verification/nullability/NullabilityAudit.java"
    for item in [args.tomcat_archive, args.core_jar, args.adapter_jar, *annotations, *sources, auditor, pins_path,browser_source,args.chrome,args.node]:
        if not item.is_file(): parser.error("Required input missing: "+str(item))
    if not re.fullmatch("[0-9a-f]{64}", args.core_sha256) or digest(args.core_jar) != args.core_sha256:
        parser.error("Selected core SHA256 mismatch before instance creation")
    if not re.fullmatch("[0-9a-f]{64}", args.adapter_sha256) or digest(args.adapter_jar) != args.adapter_sha256:
        parser.error("Selected adapter SHA256 mismatch before instance creation")
    if digest(args.tomcat_archive, "sha512") != pins["archiveSha512"]:
        parser.error("Tomcat archive differs from reviewed SHA512")
    if args.output.exists(): parser.error("Use a fresh evidence output directory")
    inputs = {str(p.resolve()): digest(p) for p in [*sources, auditor, pins_path, Path(__file__),browser_source]}
    receipt = {"namespace": namespace, "runtime": pins["version"], "runtimeSha512": pins["archiveSha512"],
               "coreJarSha256": args.core_sha256, "adapterJarSha256": args.adapter_sha256, "sourceInputs": inputs, "browserBinarySha256":digest(args.chrome),"nodeBinarySha256":digest(args.node), "checks": [], "requests": [],
               "success": False, "ownedProcessStopped": False, "ownedInstanceRemoved": False,
               "scope": "Synthetic signed-XML IdPs/current account collaborators; real Servlet container; real SAN TLS and owned Chrome; no hosted IdP, distributed store or formal S3 tool pass claim"}
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
                    '<url-pattern>/saml/*</url-pattern></servlet-mapping><servlet-mapping><servlet-name>saml</servlet-name><url-pattern>/idp/*</url-pattern></servlet-mapping></web-app>')
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
                app_origin=f"https://sp.example.test:{port}";idpa_origin=f"https://idpa.example.test:{port}";idpb_origin=f"https://idpb.example.test:{port}"
                tls=instance/"tls";tls.mkdir(mode=0o700);password=secrets.token_urlsafe(32);(tls/"password").write_text(password)
                (tls/"request.cnf").write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=sp.example.test\n[ext]\nsubjectAltName=DNS:sp.example.test,DNS:idpa.example.test,DNS:idpb.example.test,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
                for command in [["/usr/bin/openssl","req","-new","-x509","-newkey","rsa:2048","-nodes","-keyout",str(tls/"key.pem"),"-out",str(tls/"cert.pem"),"-days","1","-config",str(tls/"request.cnf"),"-sha256"],
                    ["/usr/bin/openssl","pkcs12","-export","-inkey",str(tls/"key.pem"),"-in",str(tls/"cert.pem"),"-out",str(tls/"tls.p12"),"-passout","file:"+str(tls/"password")]]:
                    subprocess.run(command,capture_output=True,check=True,timeout=20)
                public=subprocess.run(["/usr/bin/openssl","x509","-in",str(tls/"cert.pem"),"-pubkey","-noout"],capture_output=True,check=True).stdout
                der=subprocess.run(["/usr/bin/openssl","pkey","-pubin","-outform","DER"],input=public,capture_output=True,check=True).stdout
                spki=base64.b64encode(hashlib.sha256(der).digest()).decode();receipt["tls"]={"certificateSha256":digest(tls/"cert.pem"),"leafSpkiSha256":spki,"sans":["sp.example.test","idpa.example.test","idpb.example.test","127.0.0.1"],"systemTrustChanged":False}
                (base/"conf/server.xml").write_text(
                    f'<Server port="-1"><Service name="fixture"><Connector address="127.0.0.1" port="{port}" protocol="HTTP/1.1" SSLEnabled="true" scheme="https" secure="true" connectionTimeout="2000" maxHttpRequestHeaderSize="16384" maxHeaderCount="64" maxParameterCount="32" maxPostSize="150000" maxSwallowSize="150000" maxConnections="32" maxThreads="16" acceptCount="16">'
                    f'<SSLHostConfig protocols="TLSv1.3,TLSv1.2"><Certificate certificateKeystoreFile="{tls/"tls.p12"}" certificateKeystorePassword="{password}" certificateKeystoreType="PKCS12" type="RSA"/></SSLHostConfig></Connector>'
                    '<Engine name="fixture" defaultHost="localhost"><Host name="localhost" appBase="webapps" autoDeploy="false" deployOnStartup="true" unpackWARs="false"/></Engine></Service></Server>')
                credential = secrets.token_urlsafe(32)
                environment = dict(os.environ)
                environment.pop("JAVA_TOOL_OPTIONS", None); environment.pop("JDK_JAVA_OPTIONS", None)
                environment["REVETSEC_SAML_FIXTURE_CREDENTIAL"] = credential
                environment["REVETSEC_SAML_ORIGIN"]=app_origin
                environment["REVETSEC_SAML_IDP_A"]=idpa_origin
                environment["REVETSEC_SAML_IDP_B"]=idpb_origin
                environment["REVETSEC_SAML_CORE_JAR"] = str(copied_core)
                environment["REVETSEC_SAML_CORE_SHA256"] = args.core_sha256
                environment["REVETSEC_SAML_ADAPTER_JAR"] = str(copied_adapter)
                environment["REVETSEC_SAML_ADAPTER_SHA256"] = args.adapter_sha256
                with (args.output/"runtime.log").open("wb") as runtime:
                    process = subprocess.Popen([str(args.java_home/"bin/java"), "-Djava.awt.headless=true",
                        "-Dcatalina.home="+str(home), "-Dcatalina.base="+str(base),
                        "-cp", os.pathsep.join(map(str, [home/"bin/bootstrap.jar", home/"bin/tomcat-juli.jar"])),
                        "org.apache.catalina.startup.Bootstrap", "start"], stdout=runtime, stderr=runtime, env=environment)

                    context=ssl.create_default_context(cafile=str(tls/"cert.pem"))
                    deadline=time.monotonic()+15
                    while True:
                        try:
                            connection=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=3)
                            connection.request("GET","/saml/fixture/state",headers={"Host":f"sp.example.test:{port}","X-Fixture-Credential":credential})
                            reply=connection.getresponse();payload=reply.read(8192);connection.close()
                            if reply.status==200 and json.loads(payload)["origin_verified"]:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>deadline:raise RuntimeError("Pinned TLS Tomcat startup failed")
                        time.sleep(.05)
                    receipt["checks"].append({"name":"python-private-leaf-san-chain-verified","passed":True})
                    current="browser-matrix"
                    result=subprocess.run([str(args.node),str(browser_source),str(args.chrome),app_origin,idpa_origin,idpb_origin,spki,str(args.output/"browser.json")],capture_output=True,text=True,env=environment,timeout=100)
                    (args.output/"browser-process.log").write_text(result.stdout+result.stderr)
                    browser=json.loads((args.output/"browser.json").read_text());receipt["browserResult"]=browser
                    if result.returncode or not browser["success"]:raise RuntimeError("Browser matrix failed: "+str(browser.get("failure")))
                    receipt["checks"].extend(browser["checks"]);assert all(digest(Path(path))==value for path,value in inputs.items()),"Qualification source changed during run";receipt["success"]=True
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
