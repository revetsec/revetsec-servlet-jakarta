## How To Contribute

#### Basics

Pull requests and bug reports are welcomed. For enhancement pull requests, please ask first to save time! It's possible the proposed enhancement is outside the scope or design goals of the project.

This adapter's public API follows its 1.x compatibility policy, so please open an issue before starting a public-API change. A change that needs something new from core starts in the [core repository](https://github.com/revetsec/revetsec).

Report suspected security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in an issue or pull request.

No contributor license agreement is required at this time.

#### Local Build

You need JDK 17 or newer (17.0.3 at minimum), Maven 3.9 or newer, and Python 3 for the drift check. The adapter targets Java 17 whichever JDK runs the build.

The build resolves Revetsec core 1.0.0 from Maven Central. To test a coordinated core change, install the matching core source first; otherwise run the adapter build directly:

```shell
$ export JAVA_HOME=/absolute/path/to/jdk-17
$ export PATH="$JAVA_HOME/bin:$PATH"
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
```

The build compiles, runs every test (including the contract tests) and packages the JAR. Use `install` instead of `verify` to put `1.0.0` into your local Maven repository.

The routine CI verification commands pass `-Dmaven.javadoc.skip=true`. A dedicated gate runs Maven on Java 17 and Javadoc on checksum-pinned Corretto 26, with warnings fatal. To run it locally after installing core, point `REVETSEC_JAVADOC_HOME` at a JDK 26 and leave the skip flag off:

```shell
$ REVETSEC_JAVADOC_HOME=/absolute/path/to/jdk-26 mvn -B -ntp -DskipTests -Dmaven.javadoc.failOnWarnings=true verify
```

#### Gate Commands

CI runs these checks on every pull request. Run the ones your change affects before opening one.

| Check | JDK | Command |
| --- | --- | --- |
| Build and tests | 17, 21, 25, 27 | `mvn -B -ntp -Dmaven.javadoc.skip=true verify` |
| Error Prone, NullAway and SpotBugs | 21 | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pstatic-analysis,spotbugs verify` |
| Warnings-fatal Javadoc | Maven 17 / Javadoc 26 | `REVETSEC_JAVADOC_HOME=/absolute/path/to/jdk-26 mvn -B -ntp -DskipTests -Dmaven.javadoc.failOnWarnings=true verify` |
| Drift from core | none | `python3 scripts/verify-core-drift.py --core-directory ../revetsec` |
| Drift-check self-tests | none | `python3 -m unittest discover -s scripts -p 'test_*.py'` |

The [workflow guide](docs/workflows.md#build-and-compile-the-paired-source) gives the paired source compile commands, the concrete PostgreSQL reference-store wiring and the pinned M12 Tomcat runner. CI compiles both cookbook sources in its M12 container job. The [SAML](docs/saml.md#real-container-qualification) and [SCIM](docs/scim.md#real-container-qualification) guides give their own container commands. Run affected real-container checks after building core and this adapter; unit fakes alone do not establish container body, header or cookie behavior.

The build's contract tests enforce the conventions in [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md), the adapter's single package and its use of core's public API only, a list of banned source constructs, and the wording of the documentation. `ClaimsLintTests` rejects unsupported claims in any Markdown file. If it flags wording you wrote, rephrase it. An entry in `claims-allowlist.txt` is for wording that has evidence behind it, and each entry states that evidence.

#### Files Copied From Core

`NAMING_CONVENTIONS.md`, `SECURITY.md`, `LICENSE`, the shared Javadoc link indexes under `src/main/javadoc/links/`, `ClaimsLintTests` and its fixture are copies of Revetsec core's. `scripts/verify-core-drift.py` fails when they differ from the pinned core commit. Change them in core first, then copy the change here.

#### The Pinned Core Commit

CI does not resolve Revetsec core from a repository. It checks out `revetsec/revetsec` at the commit in `REVETSEC_CORE_SHA` (`.github/workflows/ci.yml`), installs it with `-DskipTests -Dmaven.javadoc.skip=true`, and builds this adapter against it. The pin is a full 40-character commit SHA, never a branch or tag, and it moves only by pull request.

The workflow currently has a nonplaceholder core SHA. Keep it pinned to a pushed compatible core commit when the adapter's public API changes.

A core change that breaks this adapter lands as a pair: this adapter's pull request pins the core pull request's head SHA, and after both merge the pin moves to the merged core commit.

#### Code Conventions

- Java 17 language level; tabs for indentation.
- Every Java source file and script starts with the Apache License 2.0 header that names `Copyright 2026 Revetware LLC.`, as in the existing files.
- Public API follows [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md). Helpers are static classes with a private constructor and verb or noun methods. There are no public records. Every public element carries JSpecify nullness annotations, every exported type carries exactly one of `@ThreadSafe`, `@NotThreadSafe` or `@Immutable`, and every public member has `@since`.
- Helpers contain no protocol logic. They apply bounded method, media, body and redirect transport checks, pass raw input to Revetsec core through its public API, and never use `com.revetsec.internal`.
- No compile or runtime dependencies. Revetsec core, the `jakarta.servlet` API and the annotation JARs are `provided`; everything else is `test` scope.
- This adapter and [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax) are twins with the same class names in different packages. A change to one is made to the other in the same pull request pair.
- Test classes are named `*Tests`. Tests use concrete request/response fixtures from Soklet's [`soklet-servlet-jakarta`](https://github.com/soklet/soklet-servlet-jakarta) where useful and focused carrier fakes for raw header/body failure cases. Use a fixed `Clock` where time matters and avoid `Thread.sleep`. The container runners exercise actual Servlet behavior.

#### Publishing

Publishing is a project-owner operation, not the last step of an ordinary contributor build. Do not run `mvn deploy`. Releases are signed and published to Maven Central by the project owner, only together with or after the Revetsec core release they require. Snapshot builds are not published.

The owner follows core's [release runbook](https://github.com/revetsec/revetsec/blob/main/RELEASING.md), including the guarded local bundle and pre-upload verification.
