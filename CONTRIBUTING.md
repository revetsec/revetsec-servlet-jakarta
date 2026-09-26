## How To Contribute

#### Basics

Pull requests and bug reports are welcomed. For enhancement pull requests, please ask first to save time! It's possible the proposed enhancement is outside the scope or design goals of the project.

This adapter is pre-release and follows Revetsec core's API, which is still being designed, so please open an issue before starting any change that touches public API. A change that needs something new from core starts in the [core repository](https://github.com/revetsec/revetsec).

Report suspected security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in an issue or pull request.

No contributor license agreement is required at this time.

#### Local Build

You need JDK 17 or newer (17.0.3 at minimum), Maven 3.9 or newer, and Python 3 for the drift check. The adapter targets Java 17 whichever JDK runs the build.

Revetsec core is not published yet, so install it from a checkout next to this one first:

```shell
$ export JAVA_HOME=/absolute/path/to/jdk-17
$ export PATH="$JAVA_HOME/bin:$PATH"
$ mvn -B -ntp -f ../revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
```

The second command compiles, runs every test (including the contract tests) and packages the JAR. Use `install` instead of `verify` to put `1.0.0-SNAPSHOT` into your local Maven repository.

Pass `-Dmaven.javadoc.skip=true` to every build for now. The adapter has no public types to document yet; Javadoc generation starts with the first one, and this file will then describe its setup.

#### Gate Commands

CI runs these checks on every pull request. Run the ones your change affects before opening one.

| Check | JDK | Command |
| --- | --- | --- |
| Build and tests | 17, 21, 25, 27 | `mvn -B -ntp -Dmaven.javadoc.skip=true verify` |
| Error Prone, NullAway and SpotBugs | 21 | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pstatic-analysis,spotbugs verify` |
| Drift from core | none | `python3 scripts/verify-core-drift.py --core-directory ../revetsec` |
| Drift-check self-tests | none | `python3 -m unittest discover -s scripts -p 'test_*.py'` |

The build's contract tests enforce the conventions in [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md), the adapter's single package and its use of core's public API only, a list of banned source constructs, and the wording of the documentation. `ClaimsLintTests` rejects unsupported claims in any Markdown file. If it flags wording you wrote, rephrase it. An entry in `claims-allowlist.txt` is for wording that has evidence behind it, and each entry states that evidence.

#### Files Copied From Core

`NAMING_CONVENTIONS.md`, `SECURITY.md`, `LICENSE`, the shared Javadoc link indexes under `src/main/javadoc/links/`, `ClaimsLintTests` and its fixture are copies of Revetsec core's. `scripts/verify-core-drift.py` fails when they differ from the pinned core commit. Change them in core first, then copy the change here.

#### The Pinned Core Commit

CI does not resolve Revetsec core from a repository. It checks out `revetsec/revetsec` at the commit in `REVETSEC_CORE_SHA` (`.github/workflows/ci.yml`), installs it with `-DskipTests -Dmaven.javadoc.skip=true`, and builds this adapter against it. The pin is a full 40-character commit SHA, never a branch or tag, and it moves only by pull request.

Until the first core commit exists, the pin is a placeholder of 40 zeros and every CI job fails with a message saying so. The project owner replaces it with the SHA of a pushed core commit.

A core change that breaks this adapter lands as a pair: this adapter's pull request pins the core pull request's head SHA, and after both merge the pin moves to the merged core commit.

#### Code Conventions

- Java 17 language level; tabs for indentation.
- Every Java source file and script starts with the Apache License 2.0 header that names `Copyright 2026 Revetware LLC.`, as in the existing files.
- Public API follows [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md). Helpers are static classes with a private constructor and verb or noun methods. There are no public records. Every public element carries JSpecify nullness annotations, every exported type carries exactly one of `@ThreadSafe`, `@NotThreadSafe` or `@Immutable`, and every public member has `@since`.
- Helpers contain no protocol logic. They pass raw input to Revetsec core through its public API and never use `com.revetsec.internal`.
- No compile or runtime dependencies. Revetsec core, the `jakarta.servlet` API and the annotation JARs are `provided`; everything else is `test` scope.
- This adapter and [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax) are twins with the same class names in different packages. A change to one is made to the other in the same pull request pair.
- Test classes are named `*Tests`. Tests use the request and response implementations from Soklet's [`soklet-servlet-jakarta`](https://github.com/soklet/soklet-servlet-jakarta) as test-scope fakes instead of mocks, use a fixed `Clock`, and never call `Thread.sleep`.

#### Publishing

Publishing is a project-owner operation, not the last step of an ordinary contributor build. Do not run `mvn deploy`. Releases are signed and published to Maven Central by the project owner, only together with or after the Revetsec core release they require. Snapshot builds are not published.
