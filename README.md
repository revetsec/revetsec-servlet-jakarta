# revetsec-servlet-jakarta

Revetsec helpers for applications on the `jakarta.servlet` API.

**This adapter is pre-release.** OAuth client, bearer, issuer, SAML, SCIM and WebAuthn transport helpers are implemented. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### What Is It?

[Revetsec](https://github.com/revetsec/revetsec) is a zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers and SCIM 2.0 servers. Its core has no framework dependency: it parses raw query strings, form bodies and header values.

This adapter connects Revetsec core to the Servlet API. Its helpers pass an `HttpServletRequest` to Revetsec core as raw input, and write Revetsec results to an `HttpServletResponse`. They apply bounded transport checks for method, media type, body size and redirect shape; core makes protocol and credential validation decisions.

This adapter is for the `jakarta.servlet` API. For the legacy `javax.servlet` API, use [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax). The two adapters are maintained as twins, with the same class names in different packages.

The helpers are static classes:

- `ServletOAuth`: the authorization response of an OAuth or OpenID Connect callback, from a GET query or a POST form, and redirect responses
- `ServletBearer`: a request's bearer token, for resource servers
- `ServletOAuthAuthorizationServer`: raw issuer authorization, token, revocation and introspection input and exact core-prepared response writing
- `ServletSaml`: bounded original-body and raw-query SAML parsing, plus exact HTTPS redirect and prepared authentication/logout POST-form responses
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

### Status

This adapter is **pre-release**, like Revetsec core. `ServletSaml` passes the original POST body, every Content-Type value and raw Redirect query to core, and writes prepared redirects/forms. The application selects IdPs, sessions, cookies and CSP. SCIM raw query/projection/conditional helpers, bounded body reads and exact prepared response writing are available through `ServletScim` and `ServletScimBodyResult`. OAuth, bearer, issuer and WebAuthn helpers are thin transport bridges; see the [paired workflow recipes](docs/workflows.md) for compiled source, concrete PostgreSQL reference-store wiring, explicit application duties and the M12 real-container runner. The [TOTP cookbook](docs/totp.md) uses the core authenticator directly and has a separate pinned Tomcat fixture; no TOTP-specific adapter API is needed. The [SCIM guide](docs/scim.md) and [SAML guide](docs/saml.md) document their separate container runners.

Revetsec has not been independently audited. That includes this adapter. Its security evidence is meant to be reproducible by anyone and will be listed in the [`docs/`](https://github.com/revetsec/revetsec/tree/main/docs) directory of the core repository as it is produced. Servlet helper unit and real-container qualification can be rerun locally; release interoperability and independent assurance gates remain tracked in core.

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
