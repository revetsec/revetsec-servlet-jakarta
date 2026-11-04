# revetsec-servlet-jakarta

Revetsec helpers for applications on the `jakarta.servlet` API.

**This adapter is pre-release.** OAuth client, bearer, issuer, SAML, SCIM and WebAuthn transport helpers are implemented. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### What Is It?

[Revetsec](https://github.com/revetsec/revetsec) is a zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers (SPs) and SCIM 2.0 servers. Its core has no framework dependency: it parses raw query strings, form bodies and header values.

This adapter connects Revetsec core to the Servlet API. Its helpers pass an `HttpServletRequest` to Revetsec core as raw input, and write Revetsec results to an `HttpServletResponse`. They apply bounded transport checks for method, media type, body size and redirect shape; core makes protocol and credential validation decisions.

This adapter is for the `jakarta.servlet` API. For the legacy `javax.servlet` API, use [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax). The two adapters are maintained as twins, with the same class names in different packages.

The helpers are static classes:

- `ServletOAuth`: the authorization response of an OAuth or OpenID Connect callback, from a GET query or a POST form, controlled rejection of other methods (including HEAD), and redirect responses
- `ServletBearer`: a request's bearer token, for resource servers
- `ServletOAuthAuthorizationServer`: bounded raw issuer authorization, token, revocation and introspection input, controlled core rejection at the header-name cutoff, and exact core-prepared response writing
- `ServletSaml`: bounded original-body, Content-Type and raw-query SAML parsing, plus exact HTTPS redirect and prepared authentication/logout POST-form responses
- `ServletScim`: a SCIM request's query, body and precondition headers, and the response for a SCIM result
- `ServletWebAuthn` and `ServletWebAuthnBodyResult`: bounded original JSON ceremony bodies and prepared browser request output

### Installation

Adapter 1.x requires Revetsec core 1.0.0 or later. JDK 17 or newer is required, with a minimum runtime of Java 17.0.3.

Revetsec core and the Servlet API are `provided` dependencies of this adapter, so your application declares all three coordinates below. The adapter is compiled against `jakarta.servlet-api` 6.1.0 (Servlet 6.1). At runtime the Servlet API comes from your servlet container, so declare it `provided` (Maven) or `compileOnly` (Gradle).

**Nothing has been published yet, including snapshots.** Until the first release, install Revetsec core and then this adapter into your local Maven repository from their source checkouts:

```shell
$ mvn -B -ntp -f revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
$ mvn -B -ntp -f revetsec-servlet-jakarta/pom.xml -Dmaven.javadoc.skip=true install
```

#### Maven

```xml
<dependency>
  <groupId>com.revetsec</groupId>
  <artifactId>revetsec-servlet-jakarta</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>com.revetsec</groupId>
  <artifactId>revetsec</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>jakarta.servlet</groupId>
  <artifactId>jakarta.servlet-api</artifactId>
  <version>6.1.0</version>
  <scope>provided</scope>
</dependency>
```

#### Gradle

A Gradle build resolves locally installed snapshots only when `mavenLocal()` is among its repositories.

```groovy
repositories {
  mavenLocal()
  mavenCentral()
}

dependencies {
  implementation 'com.revetsec:revetsec-servlet-jakarta:1.0.0-SNAPSHOT'
  implementation 'com.revetsec:revetsec:1.0.0-SNAPSHOT'
  compileOnly 'jakarta.servlet:jakarta.servlet-api:6.1.0'
}
```

### Standalone JWKS

Standalone public-key publication without an OAuth authorization server is available through `ServletJwks`; see the [JWKS usage guide](docs/jwks.md) for RS384, certificate chains and other supported algorithms.

### Shared authoritative-store integration

Use matching core and adapter versions for store-backed workflows. Implement
core's store and recovery contracts in your application, including authoritative
time, atomic transitions and recovery admission. Adapters translate HTTP input
and prepared responses; they do not provide durable storage or a recovery controller.

Handle an uncertain write separately from a confirmed transition whose output
cannot be released. Both outcomes withhold credentials and authentication proof;
neither permits replaying the operation to recover lost output. See the
[shared-store contracts](https://github.com/revetsec/revetsec/blob/main/docs/shared-clock-stores.md)
for result handling and coordinated recovery.

### Status

The SAML helpers pass the original body, Content-Type occurrences and raw
Redirect query to core and write prepared redirects or forms. The application
selects identity providers (IdPs), sessions, cookies and CSP. SCIM helpers
preserve raw queries and body bytes and write prepared responses.

See the [workflow recipes](docs/workflows.md) for routes and PostgreSQL storage
wiring, and the [SAML](docs/saml.md) and [SCIM](docs/scim.md) guides for protocol
integration. The [TOTP cookbook](docs/totp.md) calls core directly from
application-owned Servlet routes.

Revetsec has not been independently audited. That includes this adapter.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Development Verification

This adapter builds against Revetsec core from source. With `JAVA_HOME` pointing at JDK 17 or newer, and the core repository checked out next to this one:

```shell
$ mvn -B -ntp -f ../revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
$ python3 scripts/verify-core-drift.py --core-directory ../revetsec
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists every check that CI runs, and explains how CI pins the core commit it builds against.

### License

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
