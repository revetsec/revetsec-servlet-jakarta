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


"""Calibrate exact private action-policy defects through the actual pinned Servlet runtime."""
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
    parser.add_argument("--adapter-jar",type=Path,required=True)
    parser.add_argument("--adapter-sha256",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error("Use a fresh evidence directory")
    fixture=Path(__file__).resolve().parent
    recipe=fixture.parent.parent/"docs/ServletPasskeyActionsRecipe.java"
    original=recipe.read_text()
    definitions=[('ignore-proof-namespace', [('||!this.namespace.equals(proof.getCredentialNamespace())', ''), ('||!pending.namespace.equals(proof.getCredentialNamespace())', '')], 'genuine-typed-proof-context-namespace', 'main'), ('ignore-proof-ceremony', [('||!pending.ceremony.equals(proof.getCeremonyId())', '')], 'genuine-typed-proof-context-ceremony', 'main'), ('ignore-pending-object', [('||session.pending!=pending', '')], 'genuine-typed-proof-context-pending', 'main'), ('ignore-selected-target', [('&&MessageDigest.isEqual(target,context.target)', '')], 'different-owned-target-denies-and-burns', 'main'), ('clock-before-refusal-burn', [('synchronized void burn(@NonNull Session owner,@NonNull Grant exact){', 'synchronized void burn(@NonNull Session owner,@NonNull Grant exact){cleanup();')], 'withheld-approval-no-permission-writer-clock-throw', 'main'), ('burn-newer-grant', [('&&owner.grant==exact', '')], 'old-refusal-preserves-newer-grant-writer-block-throw', 'main'), ('ignore-postclose-eligibility', [('if(selected.owner!=null&&!this.sessions.publishable(selected.owner,selected.grant))throw new Denied(503);', '')], 'old-refusal-preserves-newer-grant-close-block', 'main'), ('retry-runtime-output', [('catch(RuntimeException unavailable){if(admitted)throw new IOException("Response publication failed");', 'catch(RuntimeException unavailable){')], 'runtime-writer-no-second-app-output', 'main'), ('signed-deadline-min', [('return now+Math.min(Math.max(0L,sessionDeadline-now),Duration.ofSeconds(60).toNanos());', 'return Math.min(sessionDeadline,now+Duration.ofSeconds(60).toNanos());')], 'wrap-safe-grant-duration', 'deadline')]
    for name,replacements,expected,scenario in definitions:
        for old,new in replacements:
            if original.count(old)!=1:parser.error("Private plant anchor is not exact: "+name)
    args.output.mkdir(parents=True)
    command=[sys.executable,str(fixture/"run.py"),"--tomcat-archive",str(args.tomcat_archive),"--core-jar",str(args.core_jar),
             "--core-sha256",args.core_sha256,"--adapter-jar",str(args.adapter_jar),"--adapter-sha256",args.adapter_sha256,"--java-home",str(args.java_home),"--annotations-repository",str(args.annotations_repository)]
    receipt={"sourceSha256":sha(recipe),"runnerSha256":sha(fixture/"run.py"),"calibrationSha256":sha(__file__),
             "scope":"Private defects in new application copies; no original core or adapter defect claimed", "success":False,"plants":[]}
    try:
        def run(output,override=None,scenario="main"):
            selected=command+["--output",str(output),"--scenario",scenario]
            if override: selected += ["--recipe-source",str(override)]
            completed=subprocess.run(selected,capture_output=True,text=True,timeout=120)
            (args.output/(output.name+"-process.log")).write_text(completed.stdout+completed.stderr)
            return completed.returncode,json.loads((output/"RESULT.json").read_text())
        code,control=run(args.output/"control")
        receipt["control"]={"exitCode":code,"result":str(args.output/"control/RESULT.json"),"success":control["success"]}
        assert code==0 and control["success"] and control["ownedProcessStopped"] and control["ownedInstanceRemoved"],"green-real-container-control-required"
        for name,replacements,expected,scenario in definitions:
            private=args.output/(name+"-source");private.mkdir()
            planted=private/"ServletPasskeyActionsRecipe.java";candidate=original
            for old,new in replacements:candidate=candidate.replace(old,new)
            planted.write_text(candidate)
            code,result=run(args.output/name,planted,scenario)
            failure=result.get("failure",{})
            detected=(code==1 and not result["success"] and failure.get("type")=="AssertionError"
                      and failure.get("message")==expected and result["ownedProcessStopped"] and result["ownedInstanceRemoved"])
            receipt["plants"].append({"name":name,"scenario":scenario,"sourceSha256":sha(planted),"expectedAssertion":expected,
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
