# Changelog

All notable changes to revetsec-servlet-jakarta are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Each release also states the minimum Revetsec core version and the Servlet API version it requires.

## 1.0.0 (2026-11-15)

First release. Requires Revetsec core 1.0.0, Jakarta Servlet API 6.1.0 and Java 17 or newer.

### Added

- OAuth client transport through `ServletOAuth`: raw browser callbacks become a `ServletOAuthCallbackResult`, and core-prepared redirects are written unchanged. A successful parse grants no identity until core completes the browser-bound transaction.
- Resource-server bearer extraction through `ServletBearer`.
- Issuer transport through `ServletOAuthAuthorizationServer` for application-routed issuer endpoints and exact core-prepared responses.
- SAML service provider (SP) transport through `ServletSaml`, including HTTP-POST Single Logout.
- SCIM transport through `ServletScim`, with raw query, projection and conditional helpers, bounded lazy original headers, provider-capped raw body reads (`ServletScimBodyResult`) and exact prepared response writing. Explicit overflow and unavailable I/O results expose no partial body.
- WebAuthn ceremony transport through `ServletWebAuthn`, with bounded body reads (`ServletWebAuthnBodyResult`).
- Public JSON Web Key Set publication through `ServletJwks`.
- Browser request-origin extraction through `ServletBrowserRequestOrigins`, which passes every raw `Sec-Fetch-Site` and `Origin` occurrence to core's `BrowserRequestOriginPolicy`.
- Compiled cookbook recipes in `docs/`, and a runner that exercises the SCIM recipe on a pinned real Tomcat for User and Group CRUD, PATCH, membership and transport.
