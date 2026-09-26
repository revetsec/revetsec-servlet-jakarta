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

"""Fail when this adapter drifts from a Revetsec core checkout (plan 10.1, "Drift control").

Checks:

1. Core identity. The core checkout's pom.xml builds com.revetsec:revetsec at exactly the version this adapter
   declares in its revetsec.version property, and the adapter's one core dependency uses that property with
   provided scope. With --expected-commit, the checkout's HEAD must be exactly that full commit SHA (the CI pin).
2. Verbatim copies. NAMING_CONVENTIONS.md, SECURITY.md and LICENSE are byte-identical to core's.
3. Contract-test copies. The adapter's ClaimsLintTests.java equals core's apart from its package declaration, and
   its claims fixture directory equals core's, file for file.
4. Javadoc link indexes. Every index in core's src/main/javadoc/links/manifest.json appears in the adapter's
   manifest with identical metadata and a byte-identical index file. Every index in the adapter's manifest,
   including its framework index, matches its recorded SHA-256.

Only the Python standard library is used. Exit status 0 means no drift; 1 means drift or an unusable checkout.
"""

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


NAMESPACES = {"m": "http://maven.apache.org/POM/4.0.0"}
CORE_COORDINATES = ("com.revetsec", "revetsec")
VERSION_PROPERTY = "revetsec.version"
PLACEHOLDER_COMMIT = "0" * 40

VERBATIM_FILES = ("NAMING_CONVENTIONS.md", "SECURITY.md", "LICENSE")
CLAIMS_LINT_TEST = "ClaimsLintTests.java"
CORE_CLAIMS_LINT_TEST = Path("src/test/java/com/revetsec") / CLAIMS_LINT_TEST
CLAIMS_FIXTURE = Path("src/test/resources/contract-fixtures/claims")
LINKS_DIRECTORY = Path("src/main/javadoc/links")
PACKAGE_DECLARATION = re.compile(r"(?m)^package [A-Za-z0-9_.]+;$")
MAX_DIFF_LINES = 40


class DriftError(Exception):
    """A check could not run at all, for example because a checkout is missing or malformed."""


def pom_text(project, path):
    value = project.findtext(path, namespaces=NAMESPACES)
    if value is None or not value.strip() or "${" in value:
        raise DriftError(f"POM must declare a literal value for {path}")
    return value.strip()


def read_pom(directory):
    pom = Path(directory) / "pom.xml"
    try:
        return ET.parse(pom).getroot()
    except (OSError, ET.ParseError) as exception:
        raise DriftError(f"Unable to read {pom}: {exception}") from exception


def read_commit(directory):
    return subprocess.check_output(
        ["git", "-C", str(directory), "rev-parse", "HEAD"], text=True
    ).strip()


def check_expected_commit(expected_commit, core_directory):
    """Returns the problems with the pinned commit, or an empty list."""
    if expected_commit == PLACEHOLDER_COMMIT:
        return [
            "The core pin is still the 40-zero placeholder. Set REVETSEC_CORE_SHA in .github/workflows/ci.yml "
            "to the full SHA of a pushed revetsec/revetsec commit."
        ]
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        return [
            f"Expected commit {expected_commit!r} is not a full 40-character lowercase commit SHA; branches, tags "
            "and abbreviated SHAs are not accepted."
        ]
    try:
        actual_commit = read_commit(core_directory)
    except (OSError, subprocess.CalledProcessError) as exception:
        return [f"Unable to read the core checkout's commit: {exception}"]
    if actual_commit != expected_commit:
        return [f"Core checkout is at {actual_commit}, expected the pinned {expected_commit}."]
    return []


def check_core_identity(core_directory, adapter_directory):
    core = read_pom(core_directory)
    adapter = read_pom(adapter_directory)
    problems = []

    coordinates = (pom_text(core, "m:groupId"), pom_text(core, "m:artifactId"))
    if coordinates != CORE_COORDINATES:
        problems.append(f"Core checkout builds {':'.join(coordinates)}, not {':'.join(CORE_COORDINATES)}.")

    core_version = pom_text(core, "m:version")
    declared_version = pom_text(adapter, f"m:properties/m:{VERSION_PROPERTY}")
    if core_version != declared_version:
        problems.append(
            f"Core checkout is version {core_version}, but this adapter declares {VERSION_PROPERTY} "
            f"{declared_version}. Update one of them; never override {VERSION_PROPERTY} on the command line."
        )

    core_dependencies = [
        dependency
        for dependency in adapter.findall("m:dependencies/m:dependency", NAMESPACES)
        if (dependency.findtext("m:groupId", namespaces=NAMESPACES),
            dependency.findtext("m:artifactId", namespaces=NAMESPACES)) == CORE_COORDINATES
    ]
    if len(core_dependencies) != 1:
        problems.append(f"The adapter must declare exactly one {':'.join(CORE_COORDINATES)} dependency.")
    else:
        dependency = core_dependencies[0]
        if dependency.findtext("m:version", namespaces=NAMESPACES) != "${" + VERSION_PROPERTY + "}":
            problems.append(f"The core dependency must use the version ${{{VERSION_PROPERTY}}}.")
        if dependency.findtext("m:scope", namespaces=NAMESPACES) != "provided":
            problems.append("The core dependency must have provided scope.")

    return problems, core_version


def describe_difference(label, core_bytes, adapter_bytes):
    """Returns a problem message for two differing files, with a short unified diff when both are text."""
    try:
        core_lines = core_bytes.decode("utf-8").splitlines(keepends=True)
        adapter_lines = adapter_bytes.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return f"{label} differs from core (binary content)."
    diff = list(difflib.unified_diff(core_lines, adapter_lines, "core/" + label, "adapter/" + label))
    shown = "".join(diff[:MAX_DIFF_LINES])
    if len(diff) > MAX_DIFF_LINES:
        shown += f"... ({len(diff) - MAX_DIFF_LINES} more diff lines)\n"
    if not diff:
        shown = "(the files differ only in line endings or a final newline)\n"
    return f"{label} differs from core:\n{shown.rstrip()}"


def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError:
        return None


def check_verbatim_files(core_directory, adapter_directory):
    problems = []
    for name in VERBATIM_FILES:
        core_bytes = read_bytes(Path(core_directory) / name)
        adapter_bytes = read_bytes(Path(adapter_directory) / name)
        if core_bytes is None:
            problems.append(f"Core checkout has no {name}.")
        elif adapter_bytes is None:
            problems.append(f"The adapter has no {name}; copy it from core.")
        elif core_bytes != adapter_bytes:
            problems.append(describe_difference(name, core_bytes, adapter_bytes))
    return problems


def without_package_declaration(source):
    return PACKAGE_DECLARATION.sub("package <adapter>;", source, count=1)


def check_contract_test_copies(core_directory, adapter_directory):
    problems = []

    core_test = read_bytes(Path(core_directory) / CORE_CLAIMS_LINT_TEST)
    adapter_tests = sorted((Path(adapter_directory) / "src/test/java").rglob(CLAIMS_LINT_TEST))
    if core_test is None:
        problems.append(f"Core checkout has no {CORE_CLAIMS_LINT_TEST.as_posix()}.")
    elif len(adapter_tests) != 1:
        problems.append(f"The adapter must have exactly one {CLAIMS_LINT_TEST} under src/test/java; found "
                        f"{len(adapter_tests)}.")
    else:
        core_source = without_package_declaration(core_test.decode("utf-8"))
        adapter_source = without_package_declaration(adapter_tests[0].read_text(encoding="utf-8"))
        if core_source != adapter_source:
            label = adapter_tests[0].relative_to(adapter_directory).as_posix()
            problems.append(describe_difference(label + " (package declaration ignored)",
                                                core_source.encode("utf-8"), adapter_source.encode("utf-8")))

    problems.extend(compare_directories(Path(core_directory) / CLAIMS_FIXTURE,
                                        Path(adapter_directory) / CLAIMS_FIXTURE, CLAIMS_FIXTURE.as_posix()))
    return problems


def compare_directories(core_root, adapter_root, label):
    if not core_root.is_dir():
        return [f"Core checkout has no {label}/."]
    if not adapter_root.is_dir():
        return [f"The adapter has no {label}/; copy it from core."]
    core_files = {path.relative_to(core_root).as_posix() for path in core_root.rglob("*") if path.is_file()}
    adapter_files = {path.relative_to(adapter_root).as_posix() for path in adapter_root.rglob("*") if path.is_file()}
    problems = []
    for name in sorted(core_files - adapter_files):
        problems.append(f"{label}/{name} is in core but missing from the adapter.")
    for name in sorted(adapter_files - core_files):
        problems.append(f"{label}/{name} is in the adapter but not in core.")
    for name in sorted(core_files & adapter_files):
        core_bytes = (core_root / name).read_bytes()
        adapter_bytes = (adapter_root / name).read_bytes()
        if core_bytes != adapter_bytes:
            problems.append(describe_difference(f"{label}/{name}", core_bytes, adapter_bytes))
    return problems


def read_manifest(directory, owner):
    manifest = Path(directory) / LINKS_DIRECTORY / "manifest.json"
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
        indexes = document["indexes"]
        return {entry["path"]: entry for entry in indexes}
    except (OSError, ValueError, KeyError, TypeError) as exception:
        raise DriftError(f"Unable to read the {owner} Javadoc link manifest {manifest}: {exception}") from exception


def check_javadoc_links(core_directory, adapter_directory):
    core_indexes = read_manifest(core_directory, "core")
    adapter_indexes = read_manifest(adapter_directory, "adapter")
    problems = []

    for path, core_entry in sorted(core_indexes.items()):
        label = (LINKS_DIRECTORY / path).as_posix()
        adapter_entry = adapter_indexes.get(path)
        if adapter_entry is None:
            problems.append(f"The adapter's Javadoc link manifest lacks core's index {path}.")
            continue
        if adapter_entry != core_entry:
            problems.append(f"The adapter's Javadoc link manifest entry for {path} differs from core's: "
                            f"core {json.dumps(core_entry, sort_keys=True)}, adapter "
                            f"{json.dumps(adapter_entry, sort_keys=True)}.")
        core_bytes = read_bytes(Path(core_directory) / label)
        adapter_bytes = read_bytes(Path(adapter_directory) / label)
        if core_bytes is None or adapter_bytes is None:
            problems.append(f"{label} is missing from {'core' if core_bytes is None else 'the adapter'}.")
        elif core_bytes != adapter_bytes:
            problems.append(describe_difference(label, core_bytes, adapter_bytes))

    for path, adapter_entry in sorted(adapter_indexes.items()):
        label = (LINKS_DIRECTORY / path).as_posix()
        index_bytes = read_bytes(Path(adapter_directory) / label)
        if index_bytes is None:
            problems.append(f"The adapter's Javadoc link manifest lists {path}, but {label} does not exist.")
        elif hashlib.sha256(index_bytes).hexdigest() != adapter_entry.get("sha256"):
            problems.append(f"{label} does not match the SHA-256 recorded in the adapter's manifest.")

    return problems


def verify(core_directory, adapter_directory, expected_commit=None):
    """Returns (problems, core_version). An empty problem list means no drift."""
    problems = []
    if expected_commit is not None:
        problems.extend(check_expected_commit(expected_commit, core_directory))
    identity_problems, core_version = check_core_identity(core_directory, adapter_directory)
    problems.extend(identity_problems)
    problems.extend(check_verbatim_files(core_directory, adapter_directory))
    problems.extend(check_contract_test_copies(core_directory, adapter_directory))
    problems.extend(check_javadoc_links(core_directory, adapter_directory))
    return problems, core_version


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core-directory", type=Path, required=True,
                        help="a checkout of revetsec/revetsec, such as ../revetsec")
    parser.add_argument("--adapter-directory", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="this adapter's checkout (default: the repository containing this script)")
    parser.add_argument("--expected-commit",
                        help="the full 40-character core commit the checkout must be at (CI passes its pin)")
    options = parser.parse_args(arguments)

    try:
        problems, core_version = verify(options.core_directory, options.adapter_directory, options.expected_commit)
    except (DriftError, OSError, UnicodeDecodeError) as exception:
        print(f"Core drift check could not run: {exception}", file=sys.stderr)
        return 1

    if problems:
        print(f"Core drift check failed ({len(problems)} problem{'s' if len(problems) != 1 else ''}):",
              file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1

    commit = options.expected_commit or "an unpinned working tree"
    print(f"No drift from Revetsec core {':'.join(CORE_COORDINATES)}:{core_version} at {commit}.")
    print(f"Checked: core identity, {', '.join(VERBATIM_FILES)}, {CLAIMS_LINT_TEST} and its fixture, "
          f"and the Javadoc link indexes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
