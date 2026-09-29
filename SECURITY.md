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

Revetsec has not been independently audited. Its security evidence is meant to be reproducible by anyone and will be listed in [`docs/`](https://github.com/revetsec/revetsec/tree/main/docs) of the core repository as it is produced: conformance logs, the interop matrix, the threat model with its invariant-to-test map, review ledgers, penetration-test notes, and fuzz and mutation reports. Revetsec is pre-release: so far the threat model maps the invariants of its foundations and of its JWT verification to their tests, [fuzz/README.md](https://github.com/revetsec/revetsec/blob/main/fuzz/README.md) records local fuzzing runs and planted-defect checks for the fuzz targets, and the rest of that evidence does not exist yet.

## Sealing Keys

`StateSealer` seals short strings into values that travel through the browser, such as a cookie, and opens them again. The OAuth client seals its pending authorization under a separate type label. Later protocol areas will use further labels for OpenID Connect or SAML sign-in and an OpenID Connect session reference. Whoever holds a sealing key can read every value sealed under it and can create values that every sealer holding it accepts, of every type. Treat a sealing key like a signing key.

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

## OAuth client boundary

`OAuthClient` returns raw access and refresh tokens, not an authenticated identity. Applications must not treat a token response, a token's unverified claims, or the authorization callback as proof of a user identity. The [OAuth client guide](https://github.com/revetsec/revetsec/blob/main/docs/oauth-client.md) describes callback routing, cookies, a shared pending store and application return destinations.

- A callback route passes its fixed registered URI from trusted routing configuration. The client compares that URI with the authenticated pending record before any authorization-server request. An application must not rebuild it from `Host`, forwarding headers or callback data.
- The pending source binds state and the PKCE verifier to the browser. A custom store must remove a record atomically. The in-memory store does so within one process. A sealed cookie can be used by two concurrent callbacks: each may attempt to exchange the same code. Use a durable shared atomic store when client-side at-most-once exchange is required across requests, nodes or restarts. Clear the browser cookie on every callback even when completion fails.
- Authenticated pending application data is returned after code completion. A `returnTo` value is still subject to an application allowlist before it is saved and again before it causes a redirect. Allowing an arbitrary external URL makes the application an open redirector.
- A present RFC 9207 callback `iss` must match the initiating issuer exactly. If the authorization server advertised that parameter at begin, an absent one is rejected. Multiple authorization servers without mandatory `iss` need distinct registered callback routes. Metadata issuer and endpoint checks are exact, and changed token or authorization endpoints fail before code exchange.
- Metadata and token requests have no automatic redirects, bounded bodies and deadlines. A configured URI policy checks endpoint text, but cannot prevent DNS rebinding by itself; use network egress controls when issuer or metadata URLs are tenant-supplied. Authorization-code exchange, refresh and revocation are sent once, without automatic retry after uncertain outcomes. An injected HTTP client must refuse redirects.

## JSON Web Key Sets

`JwtValidator` verifies JWTs with keys from a `JsonWebKeySource`: a `StaticJsonWebKeySource` holds keys the application already has, and a `RemoteJsonWebKeySource` fetches an identity provider's JSON Web Key Set from its URL and caches it. The [threat model](https://github.com/revetsec/revetsec/blob/main/docs/threat-model.md) describes the fetch rules in full, and [supported algorithms](https://github.com/revetsec/revetsec/blob/main/docs/supported-algorithms.md) the key rules.

- **One source per issuer.** A key source holds no issuer, and a validator trusts every key in it for the tokens of the issuer it expects. Share a source only among validators that expect the same issuer. A key's own `issuer` member binds it further: it verifies only tokens whose `iss` equals it (INV-C6). Microsoft Entra ID's v1.0 and v2.0 tokens have different issuers, and each version needs its own validator and key set; see [supported algorithms](https://github.com/revetsec/revetsec/blob/main/docs/supported-algorithms.md).
- **Tokens never choose a URL.** The key set's URL is fixed when the source is built. A token's `jku`, `x5u` and `jwk` headers are refused, never fetched, and a token cannot make Revetsec fetch anything but that URL (INV-G11).
- **Check where tenant-supplied URLs point.** Revetsec checks only the URL's text: `https`, no user information and no fragment, and the source's `OutboundUriPolicy`. It never resolves a hostname. `OutboundUriPolicy.defaultInstance()` rejects the cloud metadata endpoints it knows as of 2026-09-27 (169.254.169.254 and the rest of 169.254.0.0/16, 100.100.100.200, 168.63.129.16, fd00:ec2::254, fd00:ec2::23, fd20:ce::254, and the names `metadata.google.internal` and `metadata.goog` and every name under them), which is not every such endpoint. `OutboundUriPolicy.publicAddressesOnlyInstance()` also rejects loopback, private and other non-global addresses, and local and special-use names such as `localhost`, single-label names and every name under `internal`, `local` and `arpa`. When key-set URLs come from tenants, use `publicAddressesOnlyInstance()`, and give the source an `HttpClient` whose egress proxy enforces the destinations you allow and closes idle connections: only the proxy can stop a DNS name that points inside your network.
- **A hostile endpoint gets a bounded number of requests.** Fetches happen on the calling thread, one at a time per source, each within the source's request timeout. An unknown key refreshes the key set at most once per cooldown, a failed fetch starts a backoff that doubles up to 10 minutes, and no more than two requests start within one cooldown. A source refuses to build with an unknown-key cooldown longer than its minimum time to live (30 seconds and 1 minute by default), so that last limit holds back a call, a refresh after expiry included, only after fetches were cut short, for example by an interrupt. At the defaults, one endpoint that keeps failing gets at most 15 requests in its first hour, and 12 an hour after that. An endpoint that answers with a valid key set between its failures gets those successful requests too, but no more failing ones. Some malformed responses leave a connection open on the JDK, so a hostile endpoint can hold about that many connections open, per source.
- **Stale and removed keys.** While refreshes fail or are held back, an expired key set still answers for the keys it holds, for up to 12 hours by default (`maximumStaleness`; zero turns this off). A key the identity provider removes stops verifying at the first successful refresh after the key set's time to live, at most 6 hours by default. Revetsec has no call that discards a cached key set, so to stop trusting a key at once, build a new source and new validators over it.
- **Keys Revetsec refuses.** A key set's unusable keys are skipped with a reason that the source reports to `JoseObserver.didSkipJsonWebKey`, never the whole set: private and symmetric keys, keys for encryption, RSA keys under 2,048 bits or with a public exponent below 65,537, EC points off their curve, weak keys and others. An RSA key without `alg`, as Microsoft Entra ID publishes, is used only while exactly one RSA algorithm is allowed.
- **Keep the system clock.** Expiry, cooldown, backoff and staleness follow the source's `Clock`. A clock that stands still never lets a key set expire, so keep `Clock.systemUTC()` outside tests.

## Exceptions and Java Serialization

Revetsec's exceptions are `Serializable`, as every Java `Throwable` is, but Revetsec never deserializes anything. Each exception's constructor enforces its shape: a category, a fixed message, no cause other than the `IOException` behind a transport failure, and no suppressed exceptions. Deserialization bypasses the constructor, and Revetsec cannot check a serialized stream itself, because its source policy bans `ObjectInputStream`. So a crafted stream can produce a Revetsec exception that breaks those rules, for example one with no category or with an arbitrary cause. Do not deserialize Revetsec exceptions, or any other objects, from untrusted data.

## Security Invariants

Revetsec's security invariants are published in this section as the code that upholds them lands, each with a stable ID. The [threat model](https://github.com/revetsec/revetsec/blob/main/docs/threat-model.md) maps each one to the tests and build checks that enforce it, and states its scope; a test checks that every invariant listed here is in that map. The M3 OAuth rows are still under milestone verification; the threat model marks their current scope.

- **INV-G1** Every public parse or validate entry point returns a validated value or throws a documented `RevetsecException`, and no other `Throwable` escapes, whatever the input.
- **INV-G2** Size is checked before decoding, at every stage.
- **INV-G3** Nesting depth is bounded by explicit counters.
- **INV-G4** Every attacker-influenced work factor is bounded or unsupported.
- **INV-G5** Verified types, such as a validated JWT and its claims, have no public constructors, builders or static factories: only validation creates them.
- **INV-G6** No constructor, builder or factory yields weaker validation than the defaults. Each relaxation is an explicit compatibility mode that is reported to the observer, and the JOSE `none` algorithm and unsigned tokens are never accepted.
- **INV-G7** Random values Revetsec generates, such as sealing salts and IVs, come from `SecureRandom`.
- **INV-G8** Secrets and MACs are compared in constant time.
- **INV-G9** No secret or personal data appears in any exception or log message, `toString()` or observer event.
- **INV-G10** JCA algorithm names are pinned and JCA providers are not, so Revetsec works with any JCA provider, including hardware-backed and approved-mode ones. Each message is parsed exactly once.
- **INV-G11** Message content never chooses an outbound destination, and it causes at most one refetch of the configured JSON Web Key Set URI per cooldown.
- **INV-G12** Time checks use the injected `Clock`, with a documented clock skew.
- **INV-J1** A JWT's signature algorithm must be one the application allows (RS256 alone by default), matched exactly and case-sensitively; `none` cannot be represented.
- **INV-J2** A key serves only the algorithms of its key type and curve, and a public key is never used as an HMAC key.
- **INV-J3** A JSON Web Key is used only for verification, only for its own `alg`, and never when it carries private or symmetric members. An RSA key without `alg` is used only while exactly one RSA algorithm is allowed.
- **INV-J4** A JWT's `jwk`, `jku` and `x5u` headers cause rejection and are never fetched.
- **INV-J5** Signatures and keys are checked in shape before the JCA sees them: ECDSA signatures are fixed-length with r and s in range, EC keys lie on their curve, RSA keys are 2,048 to 16,384 bits, and malformed, small-order and ROCA-fingerprinted keys are refused.
- **INV-J6** `crit`, `b64`, `zip` and `cty` headers, encrypted (five-segment) tokens, and duplicate header or claim names are rejected.
- **INV-J7** Compact parsing counts a token's separators before splitting it, and base64url input must be in canonical form.
- **INV-J8** A JWT's `typ` is checked per profile, as a media type compared ASCII case-insensitively.
- **INV-J9** A JSON Web Key Set is bound to one URI and holds no issuer. An unknown key refreshes it at most once per cooldown, for all concurrent callers; a removed key stops verifying; stale keys are served for a bounded time; and a JWT without `kid` needs exactly one compatible key.
- **INV-C6** A JSON Web Key with an `issuer` member verifies only JWTs whose `iss` equals it. The one exception is Microsoft Entra ID's exact `{tenantid}` template, which matches only the token's own tenant.
- **INV-O1** OAuth pending state binds the code-flow parameters and initiating browser through a sealed source or an atomic store; the latter consumes once. The M3 scope and OIDC-only fields still owed are listed in the threat model.
- **INV-O2** Every authorization-code flow sends a fresh PKCE S256 challenge and never sends `plain`.
- **INV-O3** A callback issuer matches the initiating issuer exactly; a required issuer cannot be absent, and endpoint changes fail before code exchange.
- **INV-O4** An authorization error surfaces only after local state, browser-binding, route and issuer validation.
- **INV-O5** Token endpoint requests and responses have bounded URI, redirect, media, size and time rules and strict required fields.
- **INV-O6** An omitted token-response scope is interpreted using that request's scopes, never the client's defaults.
- **INV-O7** Basic credentials form-encode the ID and secret before Base64 by default, and secrets never enter request URLs.
- **INV-O8** The OAuth client yields raw credentials, never a verified identity.
- **INV-O9** Metadata issuer matches the configured issuer exactly, and each requestable endpoint passes the outbound URI policy.
- **INV-L1** The JAR has zero compile or runtime dependencies, and needs no JDK modules other than `java.base`, `java.net.http`, `java.xml`, `java.xml.crypto` and `java.logging`.
- **INV-L2** No `ObjectInputStream`, reflective deserialization or scripting.
