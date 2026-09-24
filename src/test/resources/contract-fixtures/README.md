# Contract-test fixtures

Deliberate violations of the adapter's contract tests. `ContractMetaTests` points each checker at one of these
trees and asserts that it reports exactly the seeded violations: every one of them, and none of the compliant
controls.

| Directory | Checker | Seeded violations |
|---|---|---|
| `public-api/` | `PublicApiContractTests` | a public record, missing and duplicate thread-safety markers, missing Javadoc and `@since`, missing nullness, `of*`/`create*`/`new*` factory names, a non-final concrete class, a sealed concrete class reopened by a non-sealed subclass (and a sealed one with a final subclass as a control), implicit and explicit public or protected constructors (including on a class listed in `R1_EXCEPTIONS`), members inherited from a package-private base class, and public static methods returning a verified (R17) core type (directly, as a type argument, through a type-variable bound, or inherited). `ContractMetaTests` supplies its own `R1_EXCEPTIONS` list for this tree, with a misspelled (canonical-name) entry |
| `package-dependencies/` | `PackageDependencyTests` | a core internal type used through a single-type import, a static import and a fully qualified name; a second package whose `package-info.java` lacks `@NullMarked`; and a third package with no `package-info.java` |
| `source-policy/` | `SourcePolicyTests` | one line per detection alternative, each reported by that alternative alone: calls, method references, constructors and subclasses; static setters called through an instance or an expression; constructs split across lines or spelled with Unicode escapes; Markdown (`///`) doc comments; a file outside its package's directory; plus controls, among them a `\uFFFF` literal followed by a string that names `System.out` |
| `claims/` | `ClaimsLintTests` | banned claim terms in Markdown, Javadoc (`/** */` and `///`), `package.html`, `doc-files/`, the Javadoc overview and the POM description, including terms wrapped across lines, joined by no-break spaces or dashes, or spelled with HTML entities; plus stale, malformed and too-broad allowlist entries. A copy of RevetSec core's fixture, checked by `scripts/verify-core-drift.py` |
| `core-stubs/` | (none) | not a fixture: stand-ins for RevetSec core types that do not exist yet (a verified type, a public type and an internal type). The checkers resolve them from javac's source path, and never analyze them |

The real contract tests never scan this directory: the Java files here are not on any source path, and
`ClaimsLintTests` excludes `src/test/resources/contract-fixtures/` when it lints the repository.
