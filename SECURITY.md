# Security Policy

This policy covers RevetSec core (`com.revetsec:revetsec`) and its adapters (`revetsec-soklet`, `revetsec-servlet-jakarta` and `revetsec-servlet-javax`). Each of those repositories carries an identical copy of this file.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately by emailing security@revetware.com.

Include the affected RevetSec artifact and version (or commit), a concise description of the issue, and any reproduction steps or proof-of-concept details that can be shared safely. Please do not open a public GitHub issue for suspected vulnerabilities until we have coordinated disclosure.

You should receive an acknowledgment within 3 business days. We will work with you on a coordinated disclosure timeline appropriate to the severity of the issue. Fixed vulnerabilities are published as GitHub Security Advisories, and the CHANGELOG entry for the fixing release names the GHSA or CVE ID.

GitHub private vulnerability reporting is planned for these repositories but is not enabled yet. Once it is, you can also report through a repository's **Security** tab. A `security.txt` will be published at `https://revetsec.com/.well-known/security.txt` once the website exists.

## Supported Versions

No version of RevetSec has been released. The version stays `1.0.0-SNAPSHOT` until the first release, 1.0.0.

| Release line | Status |
| --- | --- |
| `1.0.0-SNAPSHOT` and unreleased source | Unsupported development builds |

The supported-versions table and end-of-life policy will be set here with 1.0.0. Reports against development builds are still welcome.

## Scope

Reports about RevetSec-authored behavior are in scope, for example: protocol message parsing and validation, signature and token verification, pending-state handling, outbound HTTP requests, resource limits, and the adapters' translation of framework requests and responses. Reports showing that a documented default, invariant or boundary does not hold are especially appreciated.

RevetSec has no runtime dependencies, but it relies on the JDK's own cryptography, XML parsing and XML Signature implementation. The XML Signature implementation ships inside the JDK and is derived from Apache Santuario. Report vulnerabilities in the JDK itself to your JDK vendor, and keep your runtime current with the JDK's quarterly critical patch updates. RevetSec requires Java 17.0.3 or newer.

The core repository also holds test tooling that is never published, such as fuzzing, interop and verification harnesses and a scripted SAML test identity provider. A flaw there is in scope when it could hide a defect in RevetSec, for example a test partner that accepts or produces a message it should not.

## Security Boundary and Non-Claims

RevetSec parses and validates protocol messages for the application side of OAuth 2.0, OpenID Connect, SAML 2.0 and SCIM 2.0. It does not claim to secure an application or deployment end to end. In particular:

- RevetSec is not an OAuth authorization server, OpenID Provider or SAML identity provider.
- The application owns sessions, cookies, user storage, account linking, and the tenant scoping of external identities. See the [identity mapping guide](https://github.com/revetsec/revetsec/blob/main/docs/identity-mapping.md).
- For SCIM, RevetSec enforces schema and mutability rules only. Which privilege-bearing attributes (roles, entitlements, administrator flags) a given SCIM client may write is the application's authorization policy.
- Fuzzing, conformance-suite runs, interop tests, differential testing and internal reviews are evidence for their stated cases. They are not a third-party penetration test, a certification, or proof that no vulnerabilities exist.

RevetSec has not been independently audited. Its security evidence is meant to be reproducible by anyone and will be listed in [`docs/`](https://github.com/revetsec/revetsec/tree/main/docs) of the core repository as it is produced: conformance logs, the interop matrix, the threat model with its invariant-to-test map, review ledgers, penetration-test notes, and fuzz and mutation reports. RevetSec is pre-release, and none of that evidence exists yet.

## Security Invariants

RevetSec's security invariants will be published in this section, each with a stable ID. The [threat model](https://github.com/revetsec/revetsec/blob/main/docs/threat-model.md) will map every invariant to at least one test, and CI will check that map. Invariants are added as the code that upholds them lands. None are published yet, because RevetSec contains no protocol code.
