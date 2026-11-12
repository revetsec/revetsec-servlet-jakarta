# Local-first RP-Initiated Logout Servlet carrier

`ServletOidcLogoutRecipe.java` is unpublished Java 17 cookbook source around the shared `example.logout.LocalFirstLogout` recipe. It adds no core or published Servlet API. Inject one shared handler with trusted startup configuration and register one carrier at `/logout/*` in the origin's **root context**. The selected client's fixed callback is `/logout/callback`; non-root deployment or rewritten/encoded routes refuse rather than changing that callback.

The shared recipe owns the protocol composition: authorize and atomically detach the exact current local session before preparing provider logout, retain the original four-second host budget, use a selected `OidcClient` with a total deadline of at most three seconds, save one browser-bound pending record before delivery, and correlate a state-only return once. The carrier owns complete raw Servlet input and exact response emission. Neither creates a login/account nor turns a logout hint or return into authentication or provider-session-termination proof.

## Startup and application responsibilities

Construct the shared handler with a fixed HTTPS origin, a trusted selected provider/client and protected bounded pending/session backends. The client must configure that origin's `/logout/callback`. `LocalFirstLogout.Sessions.closeAuthorized` must, under one authoritative application transaction/lock, verify the current local session and stored CSRF value and close that exact session before returning its genuine retained session reference and logout hint. A denial means no close; null/throw/unavailable may have had an effect and must not be retried or reattached. Return retained credentials only for the authorized existing authenticated session. The application owns current policy, admission, account revocation, credential retention, expiry and durable recovery.

The injected `TransportAssurance` is an explicit **startup declaration**, not verification. All four values must be true: authenticated HTTPS context, original raw target, unambiguous physical headers, and bounded framing/read time. Qualify the actual connector, reverse proxy and edge before making that declaration. Servlet accessors cannot recover physical data a framework/proxy already collapsed. The carrier reads `isSecure`, scheme, Host and actual peer from the qualified connector and never trusts caller forwarding headers. Its native fixture's loopback HTTP `secure=true` flag exercises carrier branches only; it is not HTTPS, reverse-proxy or browser proof.

Protect local application sessions and retained hint storage. `OidcLogoutHint` is a credential; neither an untrusted compact token nor plain serialized session continuity is an authenticated application session. The application supplies current password/session policy separately. The private `LogoutFixture` used by verification is excluded from the common main artifact and must never be deployed.

## Fixed HTTP flow

| Request | Required behavior |
| --- | --- |
| `POST /logout` | Empty complete body, no query (including a bare `?`), exact singleton local Origin, one canonical session cookie and `X-CSRF-Token`. Content-Type may be absent or one exact form media type. No Authorization credential is admitted. |
| Default provider delivery | After local close and successful pending save, a bounded escaped POST form targets the selected provider's end-session endpoint. A restrictive fixed-origin CSP, no-store and no-referrer accompany it. The recipe does not proxy the provider logout request. |
| Explicit trusted GET delivery | A startup-selected alternative, capped at 4096 URI characters. A hint exceeding the cap refuses after local close, before pending save/delivery. Request data cannot select delivery or an arbitrary endpoint. |
| `GET /logout/callback?state=...` | Complete raw query plus the independent pending binding. Only a successful one-use pending correlation reports a returned browser. No ID token, code, session state or provider result parameter is accepted as proof. |

This carrier supplies HTTP behavior, not a browser UI. The protected local POST uses `X-CSRF-Token`; integrate it with an explicitly qualified same-origin application client and the chosen delivery mode. Receiving a form through a fetch response does not itself display or submit it. Browser navigation, rendering/CSP and provider behavior remain separate qualification gates.

Local close, provider preparation, save, return and response delivery have separate outcomes. Failure after a local close never restores that session. A possibly completed close or pending write returns no provider success and receives no automatic retry/read rescue. Errors redact exception text and credentials. A correlated return says explicitly that **provider-session termination is not confirmed**. Newer independent sessions remain alive and their cookies are never cleared by callback handling.

Every reached callback response clears only `__Host-rp-logout`; a carrier-level 400/413/503 uses `rejectCarrierRequest` for that fixed raw callback. Input the container rejects before Servlet dispatch cannot receive an application cookie response. Cookie deletion and creation remain independent Set-Cookie fields. All cookies use Secure, HttpOnly, Path=/ and SameSite=Lax for this GET return profile; a different callback binding requires a separately specified profile.

## Carrier bounds and error handling

The carrier preserves original raw query and header/cookie occurrences. It never calls Servlet parameter or cookie parsing, joins physical fields, truncates to a valid-looking prefix or reconstructs a request from forwarded headers. Bounds are 32 names/occurrences, 64-character names, 4096 characters per header value, 8192 aggregate header text and a complete 4096+1-byte body read. A declared or streamed overflow refuses with 413 before the shared handler. A nonempty body within the cap is still an invalid logout request. Query/body/header allocation and upload/read time also need trusted container/edge limits.

Interrupted input is unavailable and preserves/restores interruption; a socket timeout is unavailable without inventing a thread interrupt. Output `IOException` propagates exactly once. It is never reinterpreted as a definite unperformed logout or followed by a second response attempt. HEAD suppresses body emission; status, shared header values and body bytes otherwise pass through unchanged. No JSON marshalling, redirect rewriting, response flush/close or credential logging is added.

The shared handler has eight work permits around session/provider/pending operations. Keep a single injected handler per application profile; constructing one per request would discard that admission state. Backends must honor the supplied remaining budget; this composition does not preempt an arbitrary blocking collaborator or provide global traffic throttling.

## Local evidence and profile limits

`verification/logout-container` selects explicit core/common/test-fixture JARs by SHA256 and reviewed namespace-specific Tomcat archives by SHA512 before creating output or resources. Loaded core/common/fixture classes verify their actual selected JAR origin and hash. Strict release 17 compilation, attributed nullability and a focused startup/output-failure contract precede real-container requests. The separate JUnit-free fixture obtains a genuine authentication through actual OP/PKCE/nonce/signature validation before issuing its synthetic local session.

The native matrix covers raw duplicates and budgets, bare-query preservation, malformed/oversized/chunked carriers, exact Origin/session CSRF, local close before delivery, FORM and explicit GET profiles, independent cookies, one-use state correlation, newer-session preservation, close/save/consume faults, checked interruption versus socket timeout, eight-versus-ninth shared start/callback admission, an atomic duplicate-return race, expiry and metadata failures. Private carrier mutations deliberately collapse headers, ignore an unknown-length body, overwrite Set-Cookie fields or drop input interruption restoration. A failing-before regression records the new wrapper's former output-write retry; the fixed carrier propagates once.

The private fixture may buffer a deliberately injected cancellation response so it can first observe the handler's interrupt flag and absence of new session/proof publication, then clear only that injected interrupt before flushing. Ordinary interrupted real delivery may close a socket; the recipe does not promise a delivered 503 under interruption.

This is bounded synthetic local source/carrier evidence. It does not close real browser/TLS/customer-provider behavior, every physical framing/edge case, protected durable hint/pending backends, fleet recovery, the formal M12/tool profile or final merged-artifact qualification. TransportAssurance booleans never count as evidence for those gates. Use the selected shared recipe's own packet for its algorithm/provenance/store contracts; preserve each artifact-bound receipt when qualifying a newer merged candidate.
