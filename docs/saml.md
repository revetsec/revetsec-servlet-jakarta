# SAML HTTP-POST logout transport

Route ACS POST input through `ServletSaml.postBindingResultFor(request)` and logout POST input through `ServletSaml.postLogoutBindingResultFor(request)`. Call these before any servlet parameter parser consumes the original body. Both helpers preserve every Content-Type value and the raw query; core rejects ambiguous binding fields. The ACS parser accepts only `SAMLResponse`; the logout parser accepts one `SAMLRequest` or `SAMLResponse` and exposes its untrusted kind.

On an ACS completion, establish an application login session only for core's successful authentication result. Rotate the application session ID before binding the authenticated account to it. A rejected, unavailable or indeterminate result grants no session.

Configure the SP with `postSingleLogoutServiceUrl` and the approved IdP with `postSingleLogoutService`. A shared path may handle GET Redirect and POST logout, but both binding endpoints must be configured explicitly.

For SP-initiated logout, call `SamlServiceProvider.beginPostLogoutResult(idp, sessionReference)`, handle every result, and persist its `Prepared.getPendingLogout()` in browser-bound state before writing the form with `ServletSaml.writeLogoutPostForm(response, prepared, cspNonce)`. For a cross-site POST callback, the application-owned pending cookie requires `Secure`, `HttpOnly` and `SameSite=None`. A server-side pending store still needs an initiating-browser secret. Configure CSP to permit only the approved IdP form action and the application-generated nonce, if automatic submission is desired.

After parsing a POST logout response, pass the untrusted message, browser-bound `PendingSamlLogoutSource` and approved IdP to `completeLogoutResult`. Core validates the XML signature, exact destination, issuer, request correlation, time and replay admission. Clear pending browser state after a verified terminal status or expiry; a rejected callback does not cancel a valid pending attempt. Custom pending stores must implement conditional atomic `consumeIfMatches`; the default fails closed without consuming. Preserve core's rejected, unavailable and indeterminate branches. A remote success does not replace application-owned local session cleanup.

For an IdP-initiated POST request, pass its untrusted message and approved IdP to `acceptLogoutRequestResult`. Only an `Accepted` request may be used to match local sessions by the checked connection, NameID qualifiers and SessionIndex. After the application handles those sessions, prepare a response with `respondToPostLogoutRequestResult(request, idp, status)` and emit its `Prepared` through `ServletSaml.writeLogoutResponsePostForm(response, prepared, cspNonce)`. RelayState remains opaque and is never an application redirect destination.

The generic `writePostForm(response, form, cspNonce)` also accepts core-prepared authentication and logout forms. The typed helpers retain exact UTF-8 HTML, transient response headers and Content-Length without parameter reconstruction, URL rewriting, stream flushing or stream closing. The application selects IdPs, sets cookies/CSP, installs routes and owns sessions.

## Real-container qualification

[run.py](../verification/saml-container/run.py) compiles the paired private fixture for Java 17 and runs it on pinned Tomcat 11.0.27, bound only to `127.0.0.1`. It checks actual signed POST request and response callbacks, signature tampering before successful completion, replay rejection, exact prepared forms and headers, opaque RelayState, ACS separation, query pollution, physical header duplicates, duplicate/mixed message fields, invalid UTF-8, adapter body overflow and method mismatch. The fixture creates session references through core's public authentication API. This qualifies adapter transport; core's independent IdP interoperability tests provide protocol interoperability evidence.

The runner verifies the reviewed archive checksum in [runtime.json](../verification/saml-container/runtime.json), records source/JAR/runtime identities and check names, and removes its process and private instance on success or failure. It retains no credentials, bodies or runtime logs. The fixture routes and signing keys exist only in that private test instance.

```shell
python3 verification/saml-container/run.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-post-logout-jakarta-evidence
```
