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


"""Exact private application-source defects must hit named actual-container assertions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    if not __debug__:parser.error("Optimization disables assertions")
    for name in ["tomcat-archive","java-home","annotations-repository","checker-qual-jar","output"]:parser.add_argument("--"+name,type=Path,required=True)
    for name in ["core","adapter","store","pyranid","driver"]:
        parser.add_argument("--"+name+"-jar",type=Path,required=True);parser.add_argument("--"+name+"-sha256",required=True)
    args=parser.parse_args();fixture=Path(__file__).resolve().parent;servlet=fixture/"DurableIssuerServlet.java";original=servlet.read_text()
    definitions=[
        ("drop-object-authorization","||!path.equals(\"/resource/tenant/alice\")","","current-tenant-and-object-denied"),
        ("drop-current-account-policy","||!this.fixture.enabled.get()","","current-account-policy-denied"),
        ("misclassify-store-outage-as-invalid-token","ServletOAuthAuthorizationServer.writeResponse(response,this.fixture.server.responseForFailure(failure));","response.setHeader(\"WWW-Authenticate\",\"Bearer error=\\\"invalid_token\\\"\");send(response,401,JsonObject.builder().put(\"error\",\"Request denied\").build());","authority-outage-not-invalid-token")]
    for name,old,new,expected in definitions:
        if original.count(old)!=1:parser.error("Private exact source anchor changed: "+name)
    if args.output.exists():parser.error("Fresh output required")
    args.output.mkdir(parents=True);command=[sys.executable,"-B",str(fixture/"run.py")]
    for name in ["tomcat_archive","java_home","annotations_repository","checker_qual_jar"]:command += ["--"+name.replace("_","-"),str(getattr(args,name))]
    for name in ["core","adapter","store","pyranid","driver"]:command += ["--"+name+"-jar",str(getattr(args,name+"_jar")),"--"+name+"-sha256",getattr(args,name+"_sha256")]
    receipt={"success":False,"sourceSha256":sha(servlet),"runnerSha256":sha(fixture/"run.py"),"calibrationSha256":sha(__file__),"plants":[],"scope":"Private application-source authorization/classification defects; actual pinned Tomcat+owned PostgreSQL protocol flow; no core defect or full mutation score"}
    def run(name,override=None):
        out=args.output/name;cmd=[*command,"--output",str(out)]
        if override:cmd += ["--servlet-source",str(override)]
        completed=subprocess.run(cmd,capture_output=True,text=True,timeout=100);(args.output/(name+"-process.log")).write_text(completed.stdout+completed.stderr);return completed.returncode,json.loads((out/"RESULT.json").read_text())
    try:
        code,control=run("control");assert code==0 and control["success"]and control["ownedProcessStopped"]and control["ownedInstanceRemoved"]and control["ownedDatabaseRemoved"],"green-owned-container-control-required";receipt["control"]={"result":str(args.output/"control/RESULT.json"),"sha256":sha(args.output/"control/RESULT.json")}
        for name,old,new,expected in definitions:
            private=args.output/(name+"-source");private.mkdir();planted=private/"DurableIssuerServlet.java";planted.write_text(original.replace(old,new));code,result=run(name,planted);failure=result.get("failure",{});detected=code==1 and failure.get("type")=="AssertionError"and failure.get("message")==expected and result["ownedProcessStopped"]and result["ownedInstanceRemoved"]and result["ownedDatabaseRemoved"]
            receipt["plants"].append({"name":name,"expectedAssertion":expected,"actualFailure":failure,"detected":detected,"sourceSha256":sha(planted)});assert detected,"Named planted-defect runtime assertion required: "+name
        assert sha(servlet)==receipt["sourceSha256"]and sha(fixture/"run.py")==receipt["runnerSha256"],"Selected source changed";receipt["success"]=True
    except Exception as failure:receipt["failure"]={"type":type(failure).__name__,"message":str(failure)[:200]}
    (args.output/"CALIBRATION.json").write_text(json.dumps(receipt,indent=2)+"\n");print(json.dumps({"success":receipt["success"],"detected":sum(p["detected"]for p in receipt["plants"]),"failure":receipt.get("failure")}));return 0 if receipt["success"]else 1

if __name__=="__main__":raise SystemExit(main())
