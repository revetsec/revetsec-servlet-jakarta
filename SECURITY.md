# Security Policy

This policy covers Revetsec core (`com.revetsec:revetsec`) and its adapters (`revetsec-soklet`, `revetsec-servlet-jakarta` and `revetsec-servlet-javax`). Each of those repositories carries an identical copy of this file.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately by emailing security@revetware.com.

Include the affected Revetsec artifact and version (or commit), a concise description of the issue, and any reproduction steps or proof-of-concept details that can be shared safely. Please do not open a public GitHub issue for suspected vulnerabilities until we have coordinated disclosure.

You should receive an acknowledgment within 3 business days. We will work with you on a coordinated disclosure timeline appropriate to the severity of the issue. Fixed vulnerabilities are published as GitHub Security Advisories, and the CHANGELOG entry for the fixing release names the GHSA or CVE ID.

GitHub private vulnerability reporting is planned for these repositories but is not enabled yet. Once it is, you can also report through a repository's **Security** tab. A `security.txt` will be published at `https://revetsec.com/.well-known/security.txt` once the website exists.

## Supported Versions

No version of Revetsec has been released. The version stays `1.0.0-SNAPSHOT` until the first release, 1.0.0.

| Release line | Status |
| --- | --- |
| `1.0.0-SNAPSHOT` and unreleased source | Unsupported development builds |

The supported-versions table and end-of-life policy will be set here with 1.0.0. Reports against development builds are still welcome.

## Scope

Reports about Revetsec-authored behavior are in scope, for example: protocol message parsing and validation, signature and token verification, pending-state handling, outbound HTTP requests, resource limits, and the adapters' translation of framework requests and responses. Reports showing that a documented default, invariant or boundary does not hold are especially appreciated.

Revetsec has no runtime dependencies, but it relies on the JDK's own cryptography, XML parsing and XML Signature implementation. The XML Signature implementation ships inside the JDK and is derived from Apache Santuario. Report vulnerabilities in the JDK itself to your JDK vendor, and keep your runtime current with the JDK's quarterly critical patch updates. Revetsec requires Java 17.0.3 or newer.

The core repository also holds test tooling that is never published, such as fuzzing, interop and verification harnesses and a scripted SAML test identity provider. A flaw there is in scope when it could hide a defect in Revetsec, for example a test partner that accepts or produces a message it should not.

## Security Boundary and Non-Claims

Revetsec parses and validates protocol messages for the application side of OAuth 2.0, OpenID Connect, SAML 2.0 and SCIM 2.0. It does not claim to secure an application or deployment end to end. In particular:

- Revetsec is not an OAuth authorization server, OpenID Provider or SAML identity provider.
- The application owns sessions, cookies, user storage, account linking, and the tenant scoping of external identities. See the [identity mapping guide](https://github.com/revetsec/revetsec/blob/main/docs/identity-mapping.md).
- For SCIM, Revetsec enforces schema and mutability rules only. Which privilege-bearing attributes (roles, entitlements, administrator flags) a given SCIM client may write is the application's authorization policy.
- Fuzzing, conformance-suite runs, interop tests, differential testing and internal reviews are evidence for their stated cases. They are not a third-party penetration test, a certification, or proof that no vulnerabilities exist.

Revetsec has not been independently audited. Its security evidence is meant to be reproducible by anyone and will be listed in [`docs/`](https://github.com/revetsec/revetsec/tree/main/docs) of the core repository as it is produced: conformance logs, the interop matrix, the threat model with its invariant-to-test map, review ledgers, penetration-test notes, and fuzz and mutation reports. Revetsec is pre-release: so far the threat model maps the invariants of its foundations to their tests, [fuzz/README.md](https://github.com/revetsec/revetsec/blob/main/fuzz/README.md) records the foundations' local fuzzing runs and planted-defect checks, and the rest of that evidence does not exist yet.

## Sealing Keys

`StateSealer` seals short strings into values that travel through the browser, such as a cookie, and opens them again. As the protocol areas land, Revetsec will also seal its own state with the sealer you give it, such as a pending OAuth, OpenID Connect or SAML sign-in and an OpenID Connect session reference, under separate type labels. Whoever holds a sealing key can read every value sealed under it and can create values that every sealer holding it accepts, of every type. Treat a sealing key like a signing key.

- **One key per application.** Do not share a key between applications, or between environments such as staging and production.
- **32 random bytes.** A key is exactly 32 bytes from a cryptographically secure random source, supplied as 44 characters of standard Base64, for example the output of `openssl rand -base64 32`. Keep keys out of source control and load them from a secret store. Revetsec rejects a key whose 32 bytes are all the same, as a placeholder, but it cannot tell a guessable key from a random one.
- **Key IDs are not secret.** Every sealed value carries its key's ID in the clear, so a sealer can pick the one key that opens it. A key ID is 1 to 64 characters of ASCII letters, digits, `.`, `_`, `~` and `-`, such as `2026-09`.
- **Rotate in three phases.** Let each phase reach every instance before the next one starts; otherwise an instance can receive a value sealed under a key it does not hold yet.
  1. Add the new key as a verification key.
  2. Promote it: make it the active key, and keep the old key as a verification key.
  3. Once every value sealed under the old key has expired, remove the old key. Wait the longest lifetime you seal with, counted from when the promotion reached every instance, plus one second for the rounding of expiry times, plus the largest difference between the instances' clocks.

  A sealer holds one active key and at most 16 verification keys. Opening a value uses only the key its key ID names; Revetsec never tries the other keys.
- **Rotate at once on compromise.** If a key may have been disclosed, make a new key active and remove the disclosed key in the same step; do not keep it as a verification key, because it would go on accepting values its holder forged. Values sealed under it then fail to open with `InvalidSealedStateException`, so a user in the middle of a sign-in starts again.

What a sealed value protects, and what it does not:

- Its content is encrypted and authenticated with AES-256-GCM under a key of its own, derived with HKDF-SHA256 from the sealing key and a fresh random salt. It is bound to a context string, to its type label and to an expiry, and it opens for nothing else. Every failure to open, expiry included, is the same `InvalidSealedStateException`.
- Its key ID and its length are visible, and the length gives the exact length of its content in UTF-8 bytes. Pad the content yourself if its length is sensitive.
- It can be opened any number of times until it expires. `StateSealer` keeps no record of the values it opens, so an application that needs a value to be used once must track that itself.
- Expiry is checked against the sealer's `Clock`, so it is only as accurate as that clock.
- Salts and IVs come from the JDK's `SecureRandom`. A virtual machine resumed more than once from the same memory snapshot can repeat them. A repeated salt and IV exposes the values sealed with that pair and lets them be altered; values sealed with any other salt or IV keep their protection.

### Why sealed values carry no key commitment

AES-GCM is not key-committing: someone who knows two keys can build one ciphertext that authenticates under both. That matters to a design that tries several keys on one value, or that lets an attacker choose or influence a key, as with keys derived from passwords. Such designs add a key-commitment block.

Version 1 of the sealed format has none, because neither case applies. Every sealing key is a random secret that only the application holds, and a sealer opens a value with exactly one key, the one its key ID names. So a value that opens under one of your keys had to be sealed with that key. The only party that could build a value opening under two of your keys already holds both, and could seal anything it wanted under either. The format starts with a version byte, which leaves room for a later version with a commitment block.

## Exceptions and Java Serialization

Revetsec's exceptions are `Serializable`, as every Java `Throwable` is, but Revetsec never deserializes anything. Each exception's constructor enforces its shape: a category, a fixed message, no cause other than the `IOException` behind a transport failure, and no suppressed exceptions. Deserialization bypasses the constructor, and Revetsec cannot check a serialized stream itself, because its source policy bans `ObjectInputStream`. So a crafted stream can produce a Revetsec exception that breaks those rules, for example one with no category or with an arbitrary cause. Do not deserialize Revetsec exceptions, or any other objects, from untrusted data.

## Security Invariants

Revetsec's security invariants are published in this section as the code that upholds them lands, each with a stable ID. The [threat model](https://github.com/revetsec/revetsec/blob/main/docs/threat-model.md) maps each one to the tests and build checks that enforce it, and states its scope; CI will check that map. So far Revetsec holds only its foundations, with no protocol code, and these invariants apply to them:

- **INV-G1** Every public parse or validate entry point returns a validated value or throws a documented `RevetsecException`, and no other `Throwable` escapes, whatever the input.
- **INV-G2** Size is checked before decoding, at every stage.
- **INV-G3** Nesting depth is bounded by explicit counters.
- **INV-G4** Every attacker-influenced work factor is bounded or unsupported.
- **INV-G7** Random values Revetsec generates, such as sealing salts and IVs, come from `SecureRandom`.
- **INV-G8** Secrets and MACs are compared in constant time.
- **INV-G9** No secret or personal data appears in any exception or log message, `toString()` or observer event.
- **INV-G12** Time checks use the injected `Clock`.
- **INV-J7** base64url input must be in canonical form. (Counting a compact token's separators before splitting it arrives with JOSE.)
- **INV-L1** The JAR has zero compile or runtime dependencies, and needs no JDK modules other than `java.base`, `java.net.http`, `java.xml`, `java.xml.crypto` and `java.logging`.
- **INV-L2** No `ObjectInputStream`, reflective deserialization or scripting.
