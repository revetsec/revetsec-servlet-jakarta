# Google and Apple ID tokens at a Servlet backend

This application-owned R9/R10 cookbook source composes the shared
[provider-token application recipe](https://github.com/revetsec/revetsec/blob/main/examples/provider-backend-tokens/README.md)
with a `jakarta.servlet` carrier. The common implementation owns trusted
provider keys, exact issuers and singleton audiences, Google double-submit CSRF,
Apple server nonce/request binding, one-use attempts, account policy and local
session rotation. The Servlet source adds bounded original request extraction
and independent `Set-Cookie` emission. It adds no published adapter helper/API.

Register the injected instance at one fixed mapping. The application supplies
trusted startup configuration, a bounded source/global admission policy and
current issuer+subject account/tenant/owner policy. No email auto-linking or
account provisioning occurs here.

```java
import example.ServletProviderTokensRecipe;
import example.provider.BackendApplication;
import jakarta.servlet.ServletContext;

final class ProviderServletRegistration {
    static void register(ServletContext context, BackendApplication.Configuration configuration,
            BackendApplication.Accounts accounts, BackendApplication.Admission admission) {
        var app = BackendApplication.create(configuration, accounts, admission);
        context.addServlet("provider-tokens", new ServletProviderTokensRecipe(app))
                .addMapping("/providers/*");
    }
}
```

The corresponding routes are `/providers/google/begin`,
`/providers/google/complete`, `/providers/apple/begin`,
`/providers/apple/complete`, the browser `/providers/session`,
`/providers/account/{tenant}/{account}` and `/providers/logout`, plus their
`/providers/native/` session/account/logout equivalents. Google browser login
requires an explicit same-origin begin, then GIS configured with its returned
nonce; completion carries the original `credential` and `g_csrf_token` form.
Apple native login explicitly begins a request, keeps its private request binding,
and submits the identity token with that request's exact server nonce. Use the
returned application session for API access. Follow the common recipe's full
provider/configuration, rotation, callback-budget and recovery contracts.

## Transport contract

Install on an HTTPS connector or a separately authenticated, correctly configured
trusted proxy boundary. `isSecure()`, scheme and socket-peer context must represent
that boundary; arbitrary `Forwarded`/`X-Forwarded-*` fields are never interpreted
by this recipe. The configured exact Host, HTTPS Origin and client IDs remain
startup policy. Register only the fixed route and reject noncanonical encoded or
path-parameter route aliases. Do not run a body-consuming filter, form mapper,
`getParameter*` or Servlet cookie/session conversion before this recipe.

The source retains header occurrences, even duplicates and case variants. It
rejects more than 32 enumerated header names or occurrences, more than 8192 ASCII
header characters, an individual value over 4096 characters, and malformed
materialized fields. It reads at most **32769 bytes** to detect a body over the
32768-byte cap, including chunked requests. A declared over-limit body is refused
before a read. It never feeds a truncated prefix or a read failure to the common
application. Query presence, including an empty `?`, is retained and refused.

Configure the real edge/container's header limits, total body/read deadlines,
connection/worker/queue limits and ambiguous-framing rejection. A Servlet cannot
recover wire occurrences that an upstream proxy/container already combined or
removed, and its input stream has no portable per-read deadline setter. The
fixture uses two-second connection/upload limits, 16 connections, eight workers
and an eight-connection accept queue. These settings are local fixture inputs,
not deployment capacity qualification.

Responses use the common private/no-store JSON headers. Each cookie is a separate
`Set-Cookie` field: Google completion writes both a fresh session and pending-cookie
deletion. HEAD emits no response body and cannot complete login. Read failures
produce no new session; Tomcat may itself emit a 400 for incomplete HTTP framing
before an application 503 can be written. Request/response bodies, cookies,
nonces, provider tokens and exception messages must stay out of application logs.

The common state remains bounded, volatile and single process. A restart discards
attempts/sessions. Deployments across nodes need application-owned durable atomic
nonce/session transitions, current account/recovery policy and serving admission.
Browser logout and native logout end the local app session; neither proves
provider logout or current provider credential standing.

## Build and qualify

Build the matching core and common example first. Compile
[ServletProviderTokensRecipe.java](ServletProviderTokensRecipe.java) against the
common example JAR, core JAR, the pinned Servlet API and provided annotation JARs.
The integration source is unpublished application code, just as the common example
is; do not add it as a new product API or duplicate provider policy per namespace.

The [runner](../verification/provider-token-container/run.py) compiles the actual
shared application sources plus this carrier and its synthetic fixture with
`--release 17 -Xlint:all -Werror`. It audits explicit nullability, checks exact
selected core SHA256 and reviewed runtime SHA512 **before** creating a container,
and verifies the actual runtime `JwtValidator` class origin and selected JAR hash.
Use a fresh private output directory:

```sh
python3 verification/provider-token-container/calibrate.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0.jar \
  --core-sha256 '<exact lowercase SHA256 of the selected JAR>' \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-provider-jakarta-evidence
```

`--annotations-repository` selects an existing Maven repository containing pinned
JSpecify 1.0.1 and JSR305 3.0.2; `--common-source-directory` can select the exact
shared source directory. All selected sources/JAR/runtime identities appear in
`RESULT.json`. Runtime logs and redacted per-request response fingerprints are
retained. `calibrate.py` requires a green full real-container control before three
private carrier plants: collapsed duplicate values, accepted over-limit body
prefix, and overwritten independent cookies. Only the expected named assertion
with no compile/start/setup error and successful owned process/instance cleanup
counts as detection. Live recipe/core/adapter sources are never planted.

## Evidence boundary

The fixture runs pinned Tomcat 11.0.27 on an ephemeral loopback port with a
private credential. Its fake trusted JWKS/signing keys, account policy, clock and
nonce flows exercise actual public JWT/JWKS APIs and actual HTTP Servlet routing.
The fixture's fixed `scheme=https, secure=true` connector represents trusted test
transport; it does **not** perform a real TLS handshake. Its signing/control
endpoints and loopback opt-in must never be installed in a production application.
There is no provider client secret, live Google/Apple account or native SDK here.

A successful source-bound receipt covers local R9/R10 application-carrier behavior:
request/refusal ordering, actual signed-token/JWKS validation, nonce replay/races,
account/tenant/owner denial, session rotation/logout, oversized/truncated bodies,
source outage and independent cookie serialization. It does not close hosted GIS
browser or native Apple account/device evidence, distributed session/recovery
integration or external edge qualification. The separate S1 full OIDC RP,
S2 JWT/opaque resource/client-acquisition, S3 SP/browser/mutable-SAML and S4
restrictive SCIM query/write hosts, and formal paired M12 tool pass remain open.
