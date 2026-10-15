# Servlet OAuth, bearer, issuer and passkey workflows

These `jakarta.servlet` recipes pair with the `javax.servlet` recipes in the sibling adapter. The [Java source](ServletWorkflowRecipes.java) compiles against the built core and adapter; the [real-container fixture](../verification/m12-container/M12Servlet.java) can run the flows through Tomcat. They demonstrate transport calls and result branches. The application still registers routes and supplies trusted configuration, authentication, account decisions, browser sessions, cookies, CSRF checks and durable stores. Neither the adapter nor the fixture installs these for an application.

| Workflow | Soklet integration | javax integration | Jakarta integration | Runnable recipe or qualification entry |
| --- | --- | --- | --- | --- |
| OAuth/OIDC callback and redirect | `SokletOAuth` | `ServletOAuth` | `ServletOAuth` | Paired `ServletWorkflowRecipes.java`; M12 container fixture |
| Resource bearer | `SokletBearer` | `ServletBearer` | `ServletBearer` | Paired source; M12 container fixture |
| OAuth issuer | `SokletOAuthAuthorizationServer` | `ServletOAuthAuthorizationServer` | `ServletOAuthAuthorizationServer` | Core self-issued app; paired source; M12 container fixture |
| SAML | `SokletSaml` | `ServletSaml` | `ServletSaml` | Paired SAML container fixtures |
| SCIM | `SokletScim` | `ServletScim` | `ServletScim` | Paired SCIM container fixtures |
| WebAuthn | Core API in the Soklet passkey demo | `ServletWebAuthn` | `ServletWebAuthn` | Soklet browser demo; paired source; M12 container fixture |

The table maps integration paths and sources. A real-container result is established only by a successful source-bound runner receipt; the table itself is not a test result.

## Build and compile the paired source

From this adapter checkout, with a JDK 17 or newer and Maven 3.9 or newer:

```shell
mvn -B -ntp -f ../revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
mvn -B -ntp -Dmaven.javadoc.skip=true package
SERVLET_API_JAR="$HOME/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.1.0/jakarta.servlet-api-6.1.0.jar"
mkdir -p /private/tmp/revetsec-jakarta-workflow-recipes
"$JAVA_HOME/bin/javac" --release 17 \
  -cp "../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar:target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar:$SERVLET_API_JAR" \
  -d /private/tmp/revetsec-jakarta-workflow-recipes docs/ServletWorkflowRecipes.java
```

The source takes configured core objects and application-approved values as parameters. It is a compilable integration excerpt, not an account/session/store implementation. The real-container fixture is a disposable runnable host with explicit test-only state; its checks exercise the Servlet carrier, not a production backend.

## Durable reference backend

The paired [durable wiring source](ServletDurableBackendRecipe.java) composes this Servlet recipe with the concrete, unpublished [PostgreSQL storage example](https://github.com/revetsec/revetsec/blob/main/examples/postgresql-pending-store/README.md) in core. It uses `PostgresqlPendingAuthorizationStore` for a browser-bound, atomically consumed OAuth client callback, `PostgresqlIssuerStore` for issuer grants and replay fences, and `PostgresqlWebAuthnStore` for ceremonies and credentials. These are application examples, not adapter dependencies. The application applies [their schema](https://github.com/revetsec/revetsec/blob/main/examples/postgresql-pending-store/schema.sql) and provisions stable, separate namespaces before first traffic. Every participating JVM uses the same authoritative primary and namespace for a given store.

The source requires an application-owned `PrimaryConnectionSource` that opens a fresh primary connection within the shrinking operation budget, including pool acquisition, DNS and TLS. `writeOAuthRedirect` saves pending state before sending the redirect, so a failed or uncertain save releases no browser redirect. The issuer store compares a complete read set and reports uncertain COMMIT outcomes without claiming success; do not retry non-idempotent issuance, redemption, refresh or revocation until the application reconciles authoritative state. The WebAuthn store uses versioned conditional commits; an unknown write outcome withholds authentication proof. The app must close admission for restore, drain outstanding operations, verify an independent durable recovery marker and the persisted sealing-key state, then reconcile before reopening. The example's local recovery gate is a test fixture, not a cross-host gate.

The application also supplies its registered clients, issuer signing-key lifecycle, persistent state sealer, trusted RP ID and exact HTTPS origins, account decisions, browser sessions, cookies, CSRF and resource authorization. The paired source accepts those objects or a preconfigured builder; it cannot make them durable. Its `PrimaryConnectionSource` contract and the core example's one-primary transaction rules need a real deployment implementation. A Servlet app must supply its own shared browser-session store if it runs across nodes; the Tomcat fixture's process-local sessions are disposable.

After the build above, compile the concrete composition against the core example JAR. This uses the example's pinned dependency coordinates without adding Pyranid or PostgreSQL to the Servlet adapter:

```shell
mvn -B -ntp -f ../revetsec/examples/postgresql-pending-store/pom.xml -Dmaven.test.skip=true package
SERVLET_API_JAR="$HOME/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.1.0/jakarta.servlet-api-6.1.0.jar"
mkdir -p /private/tmp/revetsec-jakarta-durable-recipes
"$JAVA_HOME/bin/javac" --release 17 -proc:none -Xlint:all -Werror \
  -cp "../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar:target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar:$SERVLET_API_JAR:../revetsec/examples/postgresql-pending-store/target/postgresql-pending-store-1.0.0-SNAPSHOT.jar" \
  -d /private/tmp/revetsec-jakarta-durable-recipes \
  docs/ServletWorkflowRecipes.java docs/ServletDurableBackendRecipe.java
```

The core example's [OAuth/issuer probe](https://github.com/revetsec/revetsec/blob/main/examples/postgresql-pending-store/run.py) and [WebAuthn probe](https://github.com/revetsec/revetsec/blob/main/examples/postgresql-pending-store/run_webauthn.py) give the required artifact-path options with `--help`; they exercise separate JVMs, conflicts, lost COMMIT acknowledgements, outages and restart on a disposable PostgreSQL primary. They are the durable-store evidence. The M12 Tomcat runner below exercises Servlet transport with volatile fixture stores; it does not run those Servlet routes against PostgreSQL or qualify a production connection pool, distributed sessions, cross-host recovery, a physical FIDO2 key or failover.

## OAuth and OpenID Connect client callbacks

Start with the configured `OAuthClient`, persist or seal `AuthorizationRedirect.getPendingAuthorization()` for the initiating browser, set the appropriate application cookie, then call `ServletOAuth.writeRedirect(response, redirect.getAuthorizationUri())`. The helper emits an HTTP redirect with no-store and no-referrer headers. The destination must come from the configured client; never forward an untrusted request parameter as a redirect target.

On the fixed callback route, call `ServletOAuth.authorizationResponseResultFor(request)` before `getParameter*`, a JSON/form mapper or a filter consumes the body. It passes the untouched GET query or original `form_post` bytes, raw query and Content-Type occurrences up to the rejecting second value to core. The parser returns a sealed `ServletOAuthCallbackResult`; handle `Rejected` as malformed input and `TooLarge` as an oversized body. The value from `Succeeded.getResponse()` is an untrusted `AuthorizationResponse`. Pass it with the browser-bound `PendingAuthorizationSource` and the fixed callback URI from route configuration to `OAuthClient.completeAuthorizationResult`. Clear the pending browser cookie on every callback outcome. Only `Succeeded` supplies tokens; rotate the application session ID before establishing the signed-in session. Handle every non-success completion variant without establishing a session, including bound authorization errors and endpoint rejection. Network and configuration failures may still reach the application exception boundary. OIDC applications use their configured OIDC completion method after the same transport parsing and rotate the session ID after successful completion.

See `writeOAuthRedirect` and `completeOAuth` in the [compilable source](ServletWorkflowRecipes.java). The core [OAuth client guide](https://github.com/revetsec/revetsec/blob/main/docs/oauth-client.md) describes PKCE, state, issuer and pending-store requirements.

## Resource-server bearer admission

Call `ServletBearer.bearerTokenResultFor(request)` on an application-routed protected resource. Its `Absent`, `Malformed` and `Present` outcomes must stay distinct. `Present.getToken()` is only a syntactically parsed bearer credential; validate it with the configured resource audience and access-token validator or issuer, then make the application's scope and permission decision. Do not grant access because parsing returned a token.

The helper passes materialized `Authorization` occurrences up to the rejecting second value to core so duplicate or malformed values reject. A trusted edge must reject physical duplicates, ambiguous framing and requests over its header limits before a container collapses them. The app generates the appropriate `WWW-Authenticate` challenge for a missing, malformed or invalid token and avoids logging the credential. See `bearer` in the [source](ServletWorkflowRecipes.java) and the core [resource-server overview](https://github.com/revetsec/revetsec/blob/main/README.md).

## OAuth authorization-server endpoints

Register authorization, token, revocation, introspection, metadata and JWKS routes explicitly for the configured `OAuthAuthorizationServer` and exact issuer authority. `ServletOAuthAuthorizationServer.beginAuthorizationResultFor(server, request, browserBinding)` accepts the application-held random browser binding. An `InteractionRequired` result goes to the application's authenticated login/consent flow; resume and complete that interaction with core after the application decides. `Completed`, `Denied` and `Rejected` carry core-prepared responses for `writeResponse`.

The token, revocation and introspection methods take original form bytes, raw query and bounded materialized header occurrences. They return a successful or rejected core result, each with a prepared response. Call `writeResponse` only on the selected result's `getResponse()`. Metadata and JWKS use `server.metadataResponse(request.getMethod())` and `server.jwksResponse(request.getMethod())` through the same writer. The writer preserves exact body bytes, status, headers and any credential-bearing `Location`; it does not JSON-encode, rewrite URLs, flush or close the stream. Add bounded host cookies before emission, and keep credentials, redirects and responses out of logs.

Read raw bodies before Servlet parameter decoding. The application owns route/issuer association, trusted TLS and edge limits, authentication, session binding, CSRF, consent, registered clients, authoritative store, conflict/unknown-commit handling and key operations. The core [issuer application contract](https://github.com/revetsec/revetsec/blob/main/docs/oauth-server-application-contracts.md) and [self-issued runnable example](https://github.com/revetsec/revetsec/blob/main/examples/self-issued/README.md) show those responsibilities. See `beginIssuer`, `token`, `revoke`, `introspect`, `writeIssuer`, `writeIssuerMetadata` and `writeIssuerKeys` in the [paired source](ServletWorkflowRecipes.java).

## WebAuthn enrollment, sign-in and management

Bind the configured `WebAuthnRelyingParty` to the trusted HTTPS origin and RP ID. Before each POST, the application checks exact Host and Origin, its session cookie, an independent CSRF value, method and content bounds. It selects an approved account handle for enrollment and reauthentication; discoverable sign-in begins without an account assertion. Keep a fresh random browser binding in the protected session. All nodes sharing the account must use the same durable store, sealing-key policy and recovery admission gate.

Call core's `beginRegistrationResult`, `beginAuthenticationResult` or `beginReauthenticationResult`. Only a `Prepared` result contains a `WebAuthnBrowserRequest`; send it with `ServletWebAuthn.writeBrowserRequest(response, prepared.getRequest())`. This writes `{ceremonyId, publicKey}` JSON with no-store and nosniff. The browser uses `PublicKeyCredential.parseCreationOptionsFromJSON` or `parseRequestOptionsFromJSON` and submits `PublicKeyCredential.toJSON()` unchanged. Treat the returned ceremony ID as untrusted routing input.

For completion, call `ServletWebAuthn.bodyResultFor(settings, request)` before any body-consuming Servlet API. It accepts one JSON Content-Type and reads at most the configured raw-body cap plus one byte. Branch on `Read`, `Rejected` and `Unavailable`; never pass an unavailable or overflowing body to core as empty bytes. Pass a `Read` copy, ceremony ID and the same browser binding to `completeRegistrationResult` for enrollment or `completeAuthenticationResult` for sign-in. For a sensitive action, call `completeReauthenticationResult(expectedUserHandle, actionPurpose, ceremonyId, body, browserBinding)`; its `Succeeded` result requires a reauthentication ceremony for that exact account and purpose. Consume the application's one-use action authorization only after that result. Rotate the application session after successful sign-in; rejected, unavailable and indeterminate results release no proof. An uncertain store write requires recovery reconciliation before readmission.

Authorize list and remove routes with the current account session and CSRF. Require recent reauthentication or another explicit account-recovery approval before adding or removing credentials. Call `listCredentialsResult` or `removeCredentialResult` only for an application-approved account handle. A listed ID does not authenticate anyone, and removal has absent/unavailable/indeterminate branches. See the [compilable source](ServletWorkflowRecipes.java), the core [passkey browser demo](https://github.com/revetsec/revetsec/blob/main/examples/passkeys-soklet/README.md), and the [PostgreSQL WebAuthn store section](https://github.com/revetsec/revetsec/blob/main/examples/postgresql-pending-store/README.md#optional-authoritative-webauthn-store). The demo's volatile store and virtual authenticator are qualification fixtures; physical-key qualification is a separate release gate.

## Real-container run

Build core and this adapter first, then supply the reviewed Tomcat archive from [runtime.json](../verification/m12-container/runtime.json):

```shell
python3 verification/m12-container/run.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-m12-jakarta-evidence
```

The runner compiles [M12Servlet.java](../verification/m12-container/M12Servlet.java) with its [issuer](../verification/m12-container/M12Issuer.java) and [authenticator](../verification/m12-container/M12Authenticator.java) fixtures for Java 17, verifies the archive SHA-512 before extraction, binds a private container to `127.0.0.1`, and writes a source/JAR/runtime-bound `RESULT.json`. Inspect its named checks and success field. It uses a disposable credential and state; the application must replace those collaborators and qualify its own edge, browser, storage and failure behavior. The [SAML](saml.md) and [SCIM](scim.md) runners exercise their own workflows in the same container family.
