# Complete OIDC RP application host (S1)

[ServletOidcRpRecipe.java](ServletOidcRpRecipe.java) is an unpublished, complete
single-process application host for the selected S1 login scenario. It uses the
actual public `OidcClient`, bounded `InMemoryPendingAuthorizationStore` and
`ServletOAuth` APIs. Query and form-post callbacks establish a fresh application
session only after the OIDC transaction and current local account policy succeed.
This source is application code, not a new core/adapter API.

The jakarta and javax Servlet sources are reviewed namespace twins. Register the
injected instance once at the fixed `/oidc/*` route:

```java
import example.ServletOidcRpRecipe;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oidc.OidcProviderMetadata;
import jakarta.servlet.ServletContext;

final class OidcRpRegistration {
    static void register(ServletContext context, ServletOidcRpRecipe.Configuration configuration,
            OidcProviderMetadata provider, ClientAuthentication authentication,
            ServletOidcRpRecipe.Accounts accounts, ServletOidcRpRecipe.Admission admission) {
        var host = ServletOidcRpRecipe.create(configuration, provider, authentication, accounts, admission);
        var registration = context.addServlet("oidc-rp", host);
        if (registration == null || !registration.addMapping("/oidc/*").isEmpty())
            throw new IllegalStateException("OIDC route already registered");
        registration.setLoadOnStartup(1);
    }
}
```

## Trusted configuration and account policy

Configure the exact HTTPS origin, `/oidc/callback` URI, issuer and client ID at
startup. Provider metadata and client authentication are trusted startup inputs.
The production factory accepts HTTPS provider configuration, the normal outbound
URI/runtime protections, fixed metadata endpoints and trusted JWKS location. It
permits RS256, requires advertised S256 PKCE and an exact callback `iss` parameter,
uses no compatibility mode, zero JWT clock skew, a five-minute ID-token age and a
five-minute pending lifetime. The host requests `max_age=300` and `prompt=login`;
a provider must support this explicit profile, both selected response modes and
issuer response binding. This profile does not establish MFA merely from an
accepted login. The app supplies any additional authentication-strength policy.

`Accounts.findAndAuthorizeLogin` is a current, bounded, read-only lookup by the
validated issuer + subject. Return an existing eligible local account or deny;
do not create/link by email or grant permission because a JWT is valid.
`Accounts.authorize` checks current policy on every protected resource request.
The host separately enforces exact local tenant/object ownership at
`/oidc/account/{tenant}/{account}`. Supply source/global abuse policy in `Admission`
from trusted socket-peer context and current account-specific policy at lookup.
All callbacks must honor their supplied shrinking budget.

The host's monotonic budget is six seconds. Production clients have a three-second
total deadline and one-second network request timeout; JWKS has one-second/64-KiB/
eight-key bounds and no expired-key staleness. The host starts core work only with
three seconds remaining, rechecks after core/account work and before publication,
and preserves caller interruption. It does not retry endpoint, store or account
operations or reconstruct a withheld login through a later read.

## Browser and session flow

1. `GET /oidc/session` reads status and never allocates a session. An explicit
   same-origin form `POST /oidc/session` with exactly `begin=1` passes admission
   before allocating a random anonymous session and CSRF value.
2. The browser explicitly POSTs its `csrf` value to `/oidc/login/query` or
   `/oidc/login/form-post`. Exact Origin, one session cookie, one form media
   value and an exact bounded form are required. Only one pending attempt may
   belong to that current anonymous session. The host reserves its bounded state,
   calls `OidcClient.beginAuthentication`, and saves the opaque browser-bound
   pending authorization **before** emitting a provider redirect or pending cookie.
   Unavailable, refused, late or indeterminate save releases neither.
3. The callback uses the actual `ServletOAuth` raw GET/form parser before loading
   or consuming pending state. Unsupported methods, including HEAD, return 405,
   emit no body/cookie and preserve the attempt. Malformed duplicates, query/body
   protocol splits and unavailable/oversized input do not reach completion.
4. A supported callback must carry the same current anonymous browser session and
   protected pending cookie. A present Origin must be the exact configured provider
   origin. The host reserves one attempt before token/key/account work; core
   atomically consumes the opaque record and validates state, exact issuer/client/
   callback/response mode, S256 redemption, ID-token signature/issuer/audience,
   signed nonce/authentication time and applicable `at_hash`/`c_hash`.
5. Only `OidcAuthenticationResult.Succeeded` reaches current account lookup. A final
   check requires the same current session/attempt, fresh token/authentication time,
   pending lifetime and original budget. Success replaces the anonymous session
   atomically, emits a fresh application session plus pending-cookie deletion as
   separate fields, and redirects only to the fixed local `/oidc/session` URI.
   The old ID and replayed callback cannot authorize access.
6. `POST /oidc/logout` requires the exact local Origin and session CSRF. It ends the
   local session and pending admission. An already running token/key/account or
   resource-authorization callback cannot publish a replacement/session/action
   after logout. This is local application logout; RP-Initiated Logout remains a
   separate recipe/feature.

Anonymous and pending cookies are host-only Secure/HttpOnly/SameSite=None to allow
cross-site form-post delivery. Authenticated session cookies use SameSite=Lax.
All state-changing local routes still require Origin and CSRF. A real browser
must permit this cookie profile; blocked or missing cookies deny login. There is
no permissive CORS configuration or provider token exposed as an application API
bearer. Errors and success responses are private/no-store/no-referrer. Do not log
cookies, codes, redirects, provider tokens, nonces or callback bodies.

## Bounds, cleanup and failure handling

The host retains at most 128 session rows and 128 attempt rows, with a conservative
65536-byte budget for retained ASCII string payloads, including old sessions
referenced by in-flight attempts. Each app attempt uses 215 charged bytes; a
session uses 86 plus 43 while pending and its bounded local account IDs when
signed in. Shared references are deliberately charged conservatively. This is a
string-payload accounting policy, not an estimate of full JVM object/stack memory.
Eight nonblocking work permits bound concurrent core begin/completion and account
phases and their temporary objects; a ninth refuses before token or account-policy work.
Admission callbacks run before that gate and must honor their remaining budget;
the deployed container separately bounds those request workers. Pending
opaque records have independent 128-entry/512-KiB/4-KiB-per-record limits.

Cleanup rotates/examines at most 16 attempts and 16 sessions on an explicit
allocation, refusing capacity without evicting live rows. Expired rows that have
not yet been examined remain charged. Session reads can remove their expired or
future-created selected row; elapsed expiry prevents real-time lifetime extension.
Pending consumption retains core's local observed-time floor. The private test
clock explicitly catches up after rollback; this is not a production clock
fallback or a shared-clock/platform qualification.

State is volatile and single process. Restart discards local sessions and attempts.
The pending store has no public binding-discard operation: an abandoned opaque
record can remain charged until its five-minute expiry, while closed host admission
prevents it from authenticating. A distributed/restart-safe deployment needs
application-owned durable atomic pending/session transitions, coordinated recovery,
clock/platform admission and trusted connection/deployment policy. These sources
make no such deployment claim.

A busy refusal before claiming an attempt permits an explicit later user action;
there is no automatic loop. A claimed completion cannot be replayed after failure,
including an uncertain pending removal, rejected token or late account result.
Malformed input that never loads pending state leaves it bounded until expiry;
a user can explicitly end the local session before starting another flow. A
failed or uncertain save emits no authorization URL; a matching later row never
rescues the withheld redirect. A socket failure after rotation may leave an
unreachable bounded session, and the old cookie does not reconstruct its ID.

## Carrier and qualification boundary

Configure actual HTTPS/trusted-proxy authority and socket-peer context, header,
body/read, connection, worker and queue limits, and ambiguous-framing rejection
before traffic. Forwarding fields never select policy here. Raw path aliases,
header occurrence/text budgets and query presence remain checked. The adapter
reads at most 32769 callback bytes to detect 32768-byte overflow, preserving raw
Content-Type occurrences and split channels. Local action bodies have a 128-byte
cap. No `getParameter*`, Servlet cookie/session conversion or body-consuming
filter may run first. An upstream that already combines/removes physical headers
requires independent edge rejection; this host cannot recover lost bytes.

The [runner](../verification/oidc-rp-container/run.py) requires exact selected
core and adapter JAR SHA256 values, checks the reviewed Tomcat 11.0.27 SHA512,
compiles/audits actual source with Java 17 warnings fatal, and verifies actual
runtime `OidcClient` and `ServletOAuth` JAR origins. Use fresh output:

```sh
python3 verification/oidc-rp-container/calibrate.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0.jar \
  --core-sha256 '<exact selected core SHA256>' \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0.jar \
  --adapter-sha256 '<exact selected adapter SHA256>' \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-s1-jakarta-evidence
```

`--annotations-repository` selects pinned JSpecify 1.0.1, JSR305 3.0.2 and Error
Prone annotations 2.50.0. A green source-bound control is required before four
private application-host plants: cross-browser admission bypass, current-account
bypass, skipped final current-session check and ignored caller interruption.
Only the expected named live-container assertion with successful owned-process/
instance cleanup counts; compile/start/timeout failures are not detection credit.
The fixture checks byte accounting, actual PKCE/token/pending
consumption, saturation, bounded cleanup and withheld effects.

The fixture has synthetic OP/signing/account/clock/control endpoints and must never
ship as an application. It follows real authorization URLs and supplies query
responses or an actual form HTML contract, then exercises actual HTTP callbacks,
core token POSTs and JWKS validation. A Python form driver supplies no real-browser
cookie/rendering evidence. The loopback connector's fixed `secure=true` flag is
trusted test transport, not an actual TLS handshake or external-edge profile.
It uses 32 connections, 16 workers, a 16-connection queue and two-second
connection/upload bounds; these are local fixture settings, not deployment sizing.

For an **explicit injected test cancellation only**, the fixture buffers handler
output and records the still-set interrupt, exact unchanged backing session-ID
set and absence of credential/session-cookie/redirect publication **before** clearing
that injected interrupt and flushing. Direct real Tomcat interruption was also
observed to close the socket without a response. The buffered observation proves
the handler's withholding decision, not that production can always deliver a 503
while its worker remains interrupted. Other caller interruption is not cleared.

Successful local receipts establish the new S1 host component and paired carrier
behavior. Hosted OP/account/browser observations, real TLS/external edge,
distributed/recovery integration and the formal Burp/SAML Raider/ZAP S1 pass remain
open. S2 full JWT/opaque resource/client acquisition, S3 full SP/browser/mutable
SAML and S4 restrictive SCIM query/write hosts retain separate work and evidence.
