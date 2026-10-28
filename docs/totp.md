# TOTP and recovery codes with Servlet 6.1

The [compilable Servlet recipe](ServletTotpRecipe.java) routes TOTP enrollment,
confirmation, login, recovery and management through core's `TotpAuthenticator`.
It is an application example: there is no dedicated Servlet TOTP adapter API.
The parallel [javax recipe](https://github.com/revetsec/revetsec-servlet-javax/blob/main/docs/totp.md)
uses the same core operations and application boundary. Read the
[core TOTP and recovery guide](https://github.com/revetsec/revetsec/blob/main/docs/totp-recovery.md)
for the durable-record and recovery-gate contracts.

Register one `ServletTotpRecipe(totp, applicationSecurity)` instance at
`/totp/*` using your container's programmatic registration. Configure `totp`
with a durable `TotpStore`, `StateSealer`, and a coordinated
`TotpRecoveryGate`; initialize the namespace before opening traffic. The
constructor deliberately requires an `ApplicationSecurity` implementation.
The recipe does not create an account, primary authentication, an always-open
gate, a session store, or an approval policy.

| Route | Method | App admission and core operation | Successful response |
| --- | --- | --- | --- |
| `/totp/enroll` | POST | Approved account and browser binding; `beginEnrollmentResult` | Setup URI and manual key after confirmed app save |
| `/totp/replace` | POST | Fresh management approval and expected factor; `beginEnrollmentResult` | Pending replacement setup URI |
| `/totp/confirm` | POST | Approved pending enrollment and raw code; `confirmEnrollmentResult` | Factor metadata and new one-time recovery codes |
| `/totp/login` | POST | Primary-authenticated pending login and raw code; `verifyResult` | Rotated full TOTP session |
| `/totp/recovery` | POST | Primary-authenticated pending login and raw code; `consumeRecoveryCodeResult` | Rotated, restricted recovery session |
| `/totp/rotate`, `/totp/remove`, `/totp/cancel` | POST | Purpose-bound management approval; corresponding core operation | Confirmed mutation, or new recovery codes on rotation |
| `/totp/status` | GET, HEAD | Authorized account; `getStatusResult` | Nonsecret factor/pending/count metadata |

Every route enters an application-owned `RequestPermit`. It must nest with
core's recovery gate or atomically enforce the same epoch fence. The recipe
holds the permit across core work and the application transaction, checks
currentness before and after that work, closes the permit, then checks the
monotonic deadline before writing sensitive JSON or cookies. The application
must also compare epoch, factor generation, account and operation binding
inside its own authoritative completion transaction. A mere preflight epoch
lookup does not close the proof-to-session race.

Implement each `ApplicationSecurity.admit*` method to authenticate the caller,
resolve account identity from server-owned state, enforce exact Host and Origin,
reject missing or duplicate visible Cookie, Origin, CSRF and Content-Type
headers, and perform bounded body admission before calling core. For the three
code submissions, require `text/plain` with a short ASCII body read from
`getInputStream()` at a fixed cap plus one byte. Never use `getParameter*` or
decode a form body for these routes: a parameter map can hide duplicate input
and cannot preserve the raw request. Check the complete body and media type
before spending a valid code. The six-digit TOTP value remains a `String`, so
leading zeroes survive. The trusted edge and container must also reject
ambiguous framing or physical duplicates that the Servlet API collapses.

The app's pending login follows successful **primary authentication**. It has
a short fixed expiry, session cookie, CSRF secret and server-owned operation
binding; failed code attempts do not extend it. Admission checks it before
core consumption. `completeTotpLogin` and `completeRecoveryLogin` recheck and
consume it atomically, pin the factor generation and epoch, and rotate both
session and CSRF identifiers. A recovery-code proof creates only the app's
restricted recovery method, never an ordinary TOTP session or management
approval. Management routes need fresh, action-specific authorization or an
explicit approved recovery path. The fixture's simplified authorization is
test-only.

The recipe serializes JSON through core's `JsonObject` as an application-owned
choice and sets no-store, no-referrer and nosniff headers. The HEAD status
response carries the same status and representation headers as GET but emits
no body bytes. Setup secrets and plaintext recovery codes are returned only
on their confirmed one-time responses; keep them out of logs, persistent
browser storage and third-party assets. The app provides validated Secure,
HttpOnly, SameSite cookies only after confirmed login completion.

`Rejected` becomes a generic 403, `Throttled` a 429 with a bounded
`Retry-After`, and `Unavailable` or `Indeterminate` a 503. An indeterminate
enrollment or management mutation calls the app's reconciliation hook and
releases no setup secret or new recovery plaintext. An uncertain verification
or recovery-code consumption creates no session; a later attempt needs a fresh
code or approved alternate path. A proven TOTP step or recovery code may be
consumed even when a later app transaction or HTTP delivery fails. Do not
translate an uncertain commit into success or retry it blindly.

## Compile and qualify

With Java 17, built sibling core and this adapter, compile the source with
warning-fatal checks. The annotation JARs are build-time only:

```shell
mkdir -p /private/tmp/revetsec-jakarta-totp-recipe
"$JAVA_HOME/bin/javac" --release 17 -proc:none -Xlint:all -Werror \
  -cp "../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar:target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar:$HOME/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.1.0/jakarta.servlet-api-6.1.0.jar:$HOME/.m2/repository/org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar:$HOME/.m2/repository/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar" \
  -d /private/tmp/revetsec-jakarta-totp-recipe docs/ServletTotpRecipe.java
```

The [private Tomcat runner](../verification/totp-container/run.py) compiles a
disposable Java 17 application, binds Tomcat 11 to loopback and exercises the
actual Servlet request/response path. The runner verifies the checksum-pinned
runtime, records the exact source and JAR hashes, and stops only its owned
process. It is transport and example qualification, not production session,
durable store or distributed recovery qualification. Its synthetic pending
login omits fixed expiry and factor-generation pinning; those checks are
covered in the separate
[PostgreSQL TOTP fixture](https://github.com/revetsec/revetsec/tree/main/examples/postgresql-pending-store)
which exercises application pending-login and epoch fencing, but is also a
one-host test recipe.

```shell
python3 verification/totp-container/run.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-totp-jakarta-evidence
```

The current hosted adapter CI core pin predates TOTP. After the owner pushes
the updated core, advance that pin and run hosted checks; the local runner's
receipt does not imply hosted CI has passed.
