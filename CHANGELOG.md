# Changelog

All notable changes to revetsec-servlet-jakarta are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Each release also states the minimum RevetSec core version and the Servlet API version it requires.

## Unreleased

Nothing has been released. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### Added

- Repository scaffold (milestone M0), with no adapter code yet:
  - a single-module Maven build for `com.revetsec:revetsec-servlet-jakarta`, targeting Java 17, whose only non-test dependencies are RevetSec core, the `jakarta.servlet` API and annotation JARs, all `provided`;
  - the `com.revetsec.servlet.jakarta` package;
  - contract tests for public API shape, package rules, source policy and documentation wording, copied from RevetSec core and adapted to one package;
  - CI that builds RevetSec core from a pinned commit, then this adapter on JDK 17, 21, 25 and 27, and checks the files copied from core for drift;
  - the repository documents, with `NAMING_CONVENTIONS.md` and `SECURITY.md` copied from RevetSec core.
