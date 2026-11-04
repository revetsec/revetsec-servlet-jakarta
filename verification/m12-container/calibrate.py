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

"""Calibrate selected adapter regressions in private, checksum-pinned real Tomcat instances."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cases(namespace):
    root = "src/main/java/com/revetsec/servlet/" + namespace + "/"
    return [
        dict(id="oauth-redirect-cache", target=root+"ServletOAuth.java", old='        response.setHeader("Cache-Control", "no-store");', new='        response.setHeader("Cache-Control", "public");', expected="oauth-redirect-policy"),
        dict(id="oauth-query-double-decode", target=root+"ServletOAuth.java", old='query == null ? "" : query', new='query == null ? "" : java.net.URLDecoder.decode(query, java.nio.charset.StandardCharsets.UTF_8)', expected="oauth-raw-query"),
        dict(id="bearer-first-value", target=root+"ServletBearer.java", old='values.size() < 2', new='values.size() < 1', expected="bearer-physical-duplicates"),
        dict(id="issuer-redirect-status", target=root+"ServletOAuthAuthorizationServer.java", old='response.setStatus(prepared.getStatusCode());', new='response.setStatus(prepared.getStatusCode() == 303 ? 200 : prepared.getStatusCode());', expected="issuer-approved-redirect"),
        dict(id="webauthn-options-cache", target=root+"ServletWebAuthn.java", old='response.setHeader("Cache-Control", "no-store");', new='response.setHeader("Cache-Control", "public");', expected="webauthn-registration-start"),
        dict(id="webauthn-ignore-size", target=root+"ServletWebAuthn.java", old='return bytes.length > cap ? ServletWebAuthnBodyResult.Rejected.INSTANCE\n                    : new ServletWebAuthnBodyResult.Read(bytes);', new='return new ServletWebAuthnBodyResult.Read(bytes);', expected="adapter-webauthn-body-cap-plus-one"),
        dict(id="webauthn-ignore-method", target=root+"ServletWebAuthn.java", old='if (!"POST".equals(request.getMethod()) || !jsonContentType(request))', new='if (!jsonContentType(request))', expected="adapter-webauthn-body-method"),
        dict(id="issuer-header-overflow-throws", target=root+"ServletOAuthAuthorizationServer.java", old='return Map.of("", List.of());', new='throw new IllegalArgumentException("Planted header cutoff defect");', expected="adapter-issuer-header-name-overflow"),
    ]


def source_inputs(repo):
    fixture = repo/"verification/m12-container"
    paths = (sorted((repo/"src/main/java").rglob("*.java")) + sorted(fixture.glob("*.java"))
             + sorted(fixture.glob("*.py")) + [repo/"pom.xml", fixture/"runtime.json", repo/"verification/nullability/NullabilityAudit.java"])
    return {str(path.relative_to(repo)): sha(path) for path in paths}


def snapshot(repo, destination):
    for name in source_inputs(repo):
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo/name, target)


def compile_adapter(source, original, core, api, annotations, java_home, work):
    classes = work/"classes"
    classes.mkdir(parents=True)
    command = [str(java_home/"bin/javac"), "--release", "17", "-parameters", "-g", "-proc:none", "-Xlint:all", "-Werror", "-d", str(classes),
               "-cp", os.pathsep.join(map(str, [core, api, *annotations])), *map(str, sorted((source/"src/main/java").rglob("*.java")))]
    built = subprocess.run(command, capture_output=True, timeout=60)
    if built.returncode:
        raise RuntimeError("adapter-compilation-failed")
    emitted = {str(path.relative_to(classes)): path.read_bytes() for path in classes.rglob("*.class")}
    jar = work/"adapter.jar"
    with zipfile.ZipFile(original) as baseline, zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as output:
        originals = {name for name in baseline.namelist() if name.endswith(".class")}
        if set(emitted) != originals:
            raise RuntimeError("adapter-class-set-changed")
        for info in baseline.infolist():
            output.writestr(info, emitted.get(info.filename, baseline.read(info)))
    names = sorted(name[:-6].replace("/", ".") for name in emitted)
    def declarations(path):
        return subprocess.check_output([str(java_home/"bin/javap"), "-public", "-s", "-classpath", str(path), *names], timeout=30)
    if declarations(original) != declarations(jar):
        raise RuntimeError("adapter-api-changed")
    return jar, {name: hashlib.sha256(data).hexdigest() for name, data in emitted.items()}


def classify(exit_code, result, expected):
    if not result:
        return "setup-failure"
    if exit_code == 0 and result.get("success") is True:
        return "survived"
    if (exit_code == 1 and result.get("success") is False and result.get("failureKind") == "assertion"
            and result.get("failedCheck") == expected and result.get("runtimeReady") is True
            and result.get("ownedProcessStopped") is True and result.get("privateInstanceRemoved") is True
            and result.get("sourceInputsStable") is True):
        return "detected"
    return "unexpected-failure"


class CalibrationInterrupted(BaseException):
    """Propagates past per-plant setup handlers so cancellation ends the calibration."""


def interrupted(signum, frame):
    raise CalibrationInterrupted()


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=10)


def workload(source, jar, args, output, work_parent):
    command = [sys.executable, str(source/"verification/m12-container/run.py"), "--tomcat-archive", str(args.tomcat_archive),
               "--core-jar", str(args.core_jar), "--adapter-jar", str(jar), "--java-home", str(args.java_home), "--output", str(output),
               "--work-parent", str(work_parent)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        stop_group(process)
        return -1, None
    except BaseException:
        stop_group(process)
        raise
    report = output/"RESULT.json"
    return process.returncode, json.loads(report.read_text()) if report.is_file() else None


def positive(exit_code, result):
    return bool(exit_code == 0 and result and result.get("success") is True and result.get("runtimeReady") is True
                and result.get("ownedProcessStopped") is True and result.get("privateInstanceRemoved") is True
                and result.get("sourceInputsStable") is True)


def calibrate(args, repo):
    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    before = source_inputs(repo)
    pin = json.loads((repo/"verification/m12-container/runtime.json").read_text())
    if hashlib.sha512(args.tomcat_archive.read_bytes()).hexdigest() != pin["archiveSha512"]:
        raise RuntimeError("runtime-checksum-mismatch")
    annotations = [Path.home()/".m2/repository"/name for name in ["org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar", "com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar", "com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar"]]
    namespace = "jakarta" if (repo/"src/main/java/com/revetsec/servlet/jakarta").is_dir() else "javax"
    summary = dict(schemaVersion=1, namespace=namespace, success=False, sourceInputs=before, coreJarSha256=sha(args.core_jar),
                   originalAdapterJarSha256=sha(args.adapter_jar), runtime=pin["version"], archiveSha512=pin["archiveSha512"], cases=[])
    private = None
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-m12-calibration-") as temporary:
            private = Path(temporary)
            work_parent = private/"instances"; work_parent.mkdir()
            api = private/"servlet-api.jar"
            with tarfile.open(args.tomcat_archive) as archive:
                member = archive.getmember("apache-tomcat-"+pin["version"]+"/lib/servlet-api.jar")
                if not member.isfile():
                    raise RuntimeError("runtime-api-not-a-file")
                with archive.extractfile(member) as source, api.open("wb") as target:
                    shutil.copyfileobj(source, target)
            control_source = private/"control-source"; snapshot(repo, control_source)
            control, control_classes = compile_adapter(control_source, args.adapter_jar, args.core_jar, api, annotations, args.java_home, private/"control-build")
            summary["compilerControl"] = dict(jarSha256=sha(control), classfiles=control_classes, servletApiSha256=sha(api), annotationArtifacts={str(path):sha(path) for path in annotations})
            code, result = workload(control_source, control, args, output/"positive", work_parent)
            summary["positivePassed"] = positive(code, result)
            if not summary["positivePassed"]:
                raise RuntimeError("positive-container-control-failed")
            for case in cases(namespace):
                row = dict(id=case["id"], target=case["target"], expectedCheck=case["expected"], status="setup-failure")
                try:
                    source = private/(case["id"]+"-source"); snapshot(control_source, source)
                    target = source/case["target"]; text = target.read_text()
                    if text.count(case["old"]) != 1:
                        raise RuntimeError("plant-pattern-not-unique")
                    target.write_text(text.replace(case["old"], case["new"]))
                    row.update(beforeSourceSha256=hashlib.sha256(text.encode()).hexdigest(), afterSourceSha256=sha(target))
                    jar, classes = compile_adapter(source, args.adapter_jar, args.core_jar, api, annotations, args.java_home, private/(case["id"]+"-build"))
                    changed = {name:dict(before=control_classes[name], after=value) for name,value in classes.items() if control_classes[name] != value}
                    stem = case["target"].removeprefix("src/main/java/").removesuffix(".java")
                    if not changed or any(name != stem+".class" and not name.startswith(stem+"$") for name in changed):
                        raise RuntimeError("plant-changed-unrelated-classes")
                    row.update(adapterJarSha256=sha(jar), changedClassfiles=changed)
                    code, result = workload(source, jar, args, output/"mutants"/case["id"], work_parent)
                    row.update(status=classify(code, result, case["expected"]), exit=code,
                               actualCheck=result.get("failedCheck") if result else None,
                               containerReady=bool(result and result.get("runtimeReady")),
                               ownedProcessStopped=bool(result and result.get("ownedProcessStopped")),
                               privateInstanceRemoved=bool(result and result.get("privateInstanceRemoved")))
                except Exception as failure:
                    row["setupFailureType"] = type(failure).__name__
                summary["cases"].append(row)
            summary["sourceInputsStable"] = before == source_inputs(repo)
            summary["success"] = summary["sourceInputsStable"] and len(summary["cases"]) == len(cases(namespace)) and all(row["status"] == "detected" for row in summary["cases"])
    except (KeyboardInterrupt, CalibrationInterrupted):
        summary["cancelled"] = True
        summary["success"] = False
    except Exception as failure:
        summary["setupFailureType"] = type(failure).__name__
    finally:
        summary["privateWorkRemoved"] = private is not None and not private.exists()
        summary["success"] = summary["success"] and summary["privateWorkRemoved"]
        (output/"CALIBRATION.json").write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error("Python optimization disables qualification assertions")
    for name in ["tomcat-archive", "core-jar", "adapter-jar", "java-home", "output"]:
        parser.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    for name in ["tomcat_archive", "core_jar", "adapter_jar", "java_home", "output"]:
        setattr(args, name, getattr(args, name).resolve())
    signal.signal(signal.SIGTERM, interrupted)
    result = calibrate(args, Path(__file__).resolve().parents[2])
    print(json.dumps(dict(success=result["success"], cases=len(result["cases"]), detected=sum(row["status"] == "detected" for row in result["cases"]), privateWorkRemoved=result["privateWorkRemoved"])))
    return 130 if result.get("cancelled") else 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
