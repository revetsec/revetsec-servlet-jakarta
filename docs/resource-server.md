# Bearer resources, introspection and service-token reads (S2)

[ServletResourceServerRecipe.java](ServletResourceServerRecipe.java) is an
unpublished application host for the selected S2 resource/acquisition scenario.
Its two named production factories select a **fixed startup** JWT or introspection
profile. The handler never guesses from token shape, falls back to introspection
after JWT failure, or forwards an incoming credential to the downstream service.
The jakarta and javax sources are reviewed namespace twins; no adapter API is added.

```java
import example.ServletResourceServerRecipe;
import com.revetsec.oauth.AuthorizationServerMetadata;
import java.net.URI;
import jakarta.servlet.ServletContext;

final class ResourceRegistration {
    static void registerJwt(ServletContext context, ServletResourceServerRecipe.Configuration configuration,
            AuthorizationServerMetadata metadata, URI trustedJwksUri, String acquisitionSecret,
            ServletResourceServerRecipe.Accounts accounts, ServletResourceServerRecipe.Resources resources,
            ServletResourceServerRecipe.Backend backend, ServletResourceServerRecipe.Admission admission) {
        var host = ServletResourceServerRecipe.createJwt(configuration, metadata, trustedJwksUri,
                acquisitionSecret, accounts, resources, backend, admission);
        var registration = context.addServlet("account-resource", host);
        if (registration == null || !registration.addMapping(configuration.servletPath() + "/*").isEmpty())
            throw new IllegalStateException("Resource route already registered");
        registration.setLoadOnStartup(1);
    }
}
```

For the opaque profile, call `createIntrospection` with its separate trusted
introspection secret, acquisition secret and the same application collaborators.
The production factories use confidential client-secret Basic with normal form
encoding. Obtain secrets from protected startup configuration; never accept a
client, secret, issuer, key/introspection/token endpoint, audience, requested scope
or resource override from a request. Metadata must bind the exact HTTPS issuer;
JWK and all role endpoints retain normal outbound-URI and runtime protections.
Replace/reconstruct admitted application wiring when rotating its credentials.
Other confidential-authentication examples remain in their own cookbook sources.

## Credential and account policy

The JWT factory uses actual `JwtAccessTokenValidator`: strict RFC 9068 `at+jwt`,
RS256, exact issuer, configured audience, required standard claims and explicit
`tenant`/`scope`, zero skew and an 8192-character compact-token bound. Trusted
remote keys have one-second/64-KiB/eight-key limits and no expired-key staleness.
HTTP no-store/no-cache on JWKS still follows the core's bounded minimum lifetime;
it is not a promise of a new key request on every validation.

The introspection factory uses actual `TokenIntrospectionClient` at the fixed
authenticated endpoint. Each admitted validation makes its own uncached credential
check, subject to the core's distinct endpoint-health backoff. `exp`, `sub`,
`client_id`, `tenant` and `scope` are required by this explicit profile. The
configured authenticated authority can omit the RFC 7662 `iss` member; a present
issuer must match. Returned proof always names the configured authoritative
issuer. Neither missing audience nor arbitrary discovery/token-directed endpoints
are accepted. Checked endpoint rejection and unavailable/malformed service
responses are infrastructure failures, not an invalid-caller-token verdict.

Both profiles additionally require a singleton exact resource audience, live
expiry, bounded subject/client ID and a strictly typed bounded tenant claim.
`accounts:read` permits the GET route; `accounts:proxy` permits the proxy-read
route. Missing/malformed bearer fields produce 401/400 challenges; invalid
credentials produce 401, insufficient scope produces 403, and infrastructure
produces private 503 without a fabricated `invalid_token` challenge. Sender-bound
credentials need their separate proof integration; this bearer recipe adds none.

`Accounts.lookup` performs current read-only issuer + subject + client mapping.
It returns an eligible local account with a positive generation. `Accounts.authorize`
rechecks that same mapping, tenant, account generation and operation permission.
The host separately compares signed/introspected tenant, route tenant and exact
route owner before any data/backend read. `Resources.read` executes only for the
approved bounded route key. Recheck current policy and credential expiry after
collaborators and immediately before output. A changed mapping/generation,
revocation, expired proof or original deadline withholds protected data.

These callbacks are trusted application implementations and must consult current
policy and honor their shrinking budget, including connection/pool/read time.
A valid JWT is not local account membership or authorization. JWT revocation
semantics remain the configured AS lifetime plus current application policy;
introspection can observe current AS inactivity on every admitted request.

## Routes and acquired-token use

Mount one profile at its configured fixed Servlet path, for example `/api/*`:

- `GET /api/accounts/{tenant}/{account}` validates the incoming bearer, checks
  current policy and reads the application resource.
- `POST /api/accounts/{tenant}/{account}/proxy-read` accepts exactly the form
  `read=1`, checks the separate proxy scope/current policy, obtains a service
  credential and performs a **read-only fixed-target GET** through `Backend`.

`ClientCredentialsTokenSource` uses its separate confidential client and fixed
`backend:read` scope/resource indicator. Caller form fields cannot override them.
Its valid server-side credential cache is the core source's existing cache; the
host adds no incoming-token or authorization cache. Acquired credentials require
Bearer type, a live explicit expiry and safe bounded header serialization. They
are never returned to the caller, placed in URLs, or substituted for local account
policy. The backend validates its own audience, service principal,
scope and current service permissions.

`Backend.read` must use a trusted fixed HTTPS target, approved route key, no
redirect following or automatic retry, bounded response/body size and the original
remaining deadline. The fixture performs real HTTP GETs and validates the actual
service JWT at its synthetic backend. The production application supplies its
actual bounded backend transport. An unbounded HTTP client/body reader does not
satisfy that collaborator contract.

A known downstream 401 invalidates **only the exact acquired AccessToken instance**
even when output is withheld, then returns private 503 without a caller credential
challenge. The request does not retry. A later explicit authorized request may
acquire a replacement. Other backend/transport errors withhold data; they do not
silently switch credentials. Early renewal can retain a still-valid old service
token under core policy, but an expired or explicitly invalidated token is not a
fallback. The qualified outage case expires the old token first.

The downstream operation is a read. This source implements no mutation, generic
RPC, user-token exchange or side-effect reconciliation. A mutation would need a
separate factual known/unknown-outcome design before adding it; a final refusal
cannot conceal a completed business change.

## Work, carrier and serving limits

All expensive validation, admission, account, data, acquisition and backend work
is inside eight nonblocking permits. A ninth refuses before provider or policy
work. The six-second host budget is monotonic; core operations have a three-second
total deadline and one-second request timeout. Each core phase starts only with
three seconds remaining. Current policy/expiry and cancellation are checked between
collaborators; late work releases no protected output. Preserve interruption.

Use actual HTTPS or a separately authenticated trusted proxy/edge policy for
scheme, Host and peer. Arbitrary forwarding fields never configure this host.
Require canonical fixed routes, one bounded bearer source and no ambient Cookie
or query credentials. A present Origin must be the exact configured origin; no
permissive CORS policy is added. GET bodies are refused, including chunked input.
Proxy-read requires one form media field, exactly `read=1`, and a complete body of
at most 128 bytes (the rejecting read detects byte129). Preserve duplicate headers;
limits are 32 names/occurrences, 16384 ASCII header characters and 8192 per value.
No `getParameter*`, body-consuming filter or Servlet cookie/session conversion
runs first. HEAD cannot read a protected resource and emits no response body.

The edge/container owns framing, wire duplicates, request/header/body-read,
connection, queue and worker limits. A Servlet cannot recover fields already
combined or dropped upstream or set a portable input-stream read deadline.
Responses have no-store/no-cache/no-referrer/nosniff, no session cookie and no
credential-bearing redirect. Do not log tokens, Basic secrets, authorization
fields, request bodies, protected data or exception messages.

## Qualification and boundaries

Run against the reviewed Tomcat 11.0.27 archive, matching core/adapter artifacts
and a fresh evidence directory:

```sh
python3 verification/resource-server-container/calibrate.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --core-sha256 '<exact selected core SHA256>' \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar \
  --adapter-sha256 '<exact selected adapter SHA256>' \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-s2-jakarta-evidence
```

`--annotations-repository` selects pinned JSpecify1.0.1, JSR3053.0.2 and Error
Prone annotations2.50.0. The runner rejects hash mismatches before creating a
container, compiles Java17 with warnings fatal, audits explicit nullability and
checks actual core/ServletBearer JAR origins. Exact sources/runtime/artifacts,
redacted request fingerprints and owned process/instance cleanup appear in receipts.
The four private host defects remove tenant/object binding, final current-policy
check, exact expiry or exact rejected-instance invalidation. Only the expected
named live assertion after a green control counts; setup/timeout failures do not.

The actual new-candidate failing-before expiry regression is preserved separately:
when lookup advanced time past E, the original handler returned401 but still
invoked data read. The fixed handler checks again before starting that work.
The fixture also checks real Basic form encoding, JWT/opaque isolation, current
AS inactivity, service-token issuance/use/cache/invalidation, policy/generation
changes and exact expiry during reads, all work permits and withheld secrets.

The synthetic AS/JWKS/account/data/backend controls are private fixtures, never
production endpoints. No real service account/customer data or external service
is used. The fixed loopback secure flag does not perform a real TLS handshake.
The host has no ambient browser session to rotate; every request uses its explicit
credential and current authorization. Applicable browser/trusted-edge, durable/
distributed/current-policy deployment and formal paired S2 tool observations remain
separate gates. S3/S4 and the final ten-family carrier ledger retain their own work.

For explicit injected test cancellation only, buffered output is observed before
clearing the fixture's injected thread interrupt: it must remain set and the
handler must have withheld data/credential/challenge/cookie/redirect output. This
does not claim that a production interrupted socket always delivers a503.
