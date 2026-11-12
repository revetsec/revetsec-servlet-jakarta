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


"""Calibrate private logout carrier multiplicity/body/cookie defects in the actual pinned container."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    if not __debug__: parser.error("Python optimization disables qualification assertions")
    parser.add_argument("--tomcat-archive",type=Path,required=True)
    parser.add_argument("--core-jar",type=Path,required=True)
    parser.add_argument("--core-sha256",required=True)
    parser.add_argument("--java-home",type=Path,required=True)
    parser.add_argument("--annotations-repository",type=Path,default=Path.home()/".m2/repository")
    parser.add_argument("--common-jar",type=Path,required=True)
    parser.add_argument("--common-sha256",required=True)
    parser.add_argument("--fixture-jar",type=Path,required=True)
    parser.add_argument("--fixture-sha256",required=True)
    parser.add_argument("--fixture-supplement",action="store_true")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error("Use a fresh evidence directory")
    fixture=Path(__file__).resolve().parent
    recipe=fixture.parent.parent/"docs/ServletOidcLogoutRecipe.java"
    original=recipe.read_text()
    definitions=[
        ("collapse-physical-header-values",[("List.copyOf(copy)","List.of(copy.get(0))")],"carrier-duplicate-csrf-before-local-close"),
        ("ignore-unknown-length-body",[("readNBytes(MAXIMUM_BODY+1)","readNBytes(request.getContentLengthLong()<0?0:MAXIMUM_BODY+1)")],"chunked-overflow-not-valid-prefix"),
        ("overwrite-cookie-fields",[("response.addHeader(\"Set-Cookie\",cookie)","response.setHeader(\"Set-Cookie\",cookie)")],"separate-session-and-pending-cookie-fields"),
        ("ignore-interrupted-input",[("if(unavailable instanceof java.io.InterruptedIOException&&!(unavailable instanceof java.net.SocketTimeoutException))Thread.currentThread().interrupt();","")],"interrupted-input-preserves-flag-before-fixture-clear")]
    for name,replacements,expected in definitions:
        for old,new in replacements:
            if original.count(old)!=1:parser.error("Private plant anchor is not exact: "+name)
    args.output.mkdir(parents=True)
    command=[sys.executable,str(fixture/"run.py"),"--tomcat-archive",str(args.tomcat_archive),"--core-jar",str(args.core_jar),
             "--core-sha256",args.core_sha256,"--common-jar",str(args.common_jar),"--common-sha256",args.common_sha256,"--fixture-jar",str(args.fixture_jar),"--fixture-sha256",args.fixture_sha256,"--java-home",str(args.java_home),"--annotations-repository",str(args.annotations_repository)]
    if args.fixture_supplement:command += ["--fixture-supplement"]
    receipt={"sourceSha256":sha(recipe),"runnerSha256":sha(fixture/"run.py"),"calibrationSha256":sha(__file__),
             "scope":"Private defects in new Servlet logout carrier copies; no existing core/common defect claimed", "success":False,"plants":[]}
    try:
        def run(output,override=None):
            selected=command+["--output",str(output)]
            if override: selected += ["--recipe-source",str(override)]
            completed=subprocess.run(selected,capture_output=True,text=True,timeout=90)
            (args.output/(output.name+"-process.log")).write_text(completed.stdout+completed.stderr)
            return completed.returncode,json.loads((output/"RESULT.json").read_text())
        code,control=run(args.output/"control")
        receipt["control"]={"exitCode":code,"result":str(args.output/"control/RESULT.json"),"success":control["success"]}
        assert code==0 and control["success"] and control["ownedProcessStopped"] and control["ownedInstanceRemoved"],"green-real-container-control-required"
        for name,replacements,expected in definitions:
            private=args.output/(name+"-source");private.mkdir()
            planted=private/"ServletOidcLogoutRecipe.java";candidate=original
            for old,new in replacements:candidate=candidate.replace(old,new)
            planted.write_text(candidate)
            code,result=run(args.output/name,planted)
            failure=result.get("failure",{})
            detected=(code==1 and not result["success"] and failure.get("type")=="AssertionError"
                      and failure.get("message")==expected and result["ownedProcessStopped"] and result["ownedInstanceRemoved"])
            receipt["plants"].append({"name":name,"sourceSha256":sha(planted),"expectedAssertion":expected,
                                      "actualFailure":failure,"detected":detected,"result":str(args.output/name/"RESULT.json")})
            assert detected,"Expected named live-container assertion required: "+name
        assert sha(recipe)==receipt["sourceSha256"],"Live cookbook source changed"
        receipt["success"]=True
    except Exception as failure:
        receipt["failure"]={"type":type(failure).__name__,"message":str(failure)[:300]}
    finally:
        (args.output/"CALIBRATION.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps({"success":receipt["success"],"detected":sum(p["detected"] for p in receipt["plants"]),"failure":receipt.get("failure")}))
    return 0 if receipt["success"] else 1


if __name__=="__main__": raise SystemExit(main())
