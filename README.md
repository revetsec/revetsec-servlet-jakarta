# revetsec-servlet-jakarta

RevetSec helpers for applications on the `jakarta.servlet` API.

**This adapter is pre-release, and no adapter code exists yet.** The repository holds the build, contract tests and CI configuration. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### What Is It?

[RevetSec](https://github.com/revetsec/revetsec) is a zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers and SCIM 2.0 servers. Its core has no framework dependency: it parses raw query strings, form bodies and header values.

This adapter connects RevetSec core to the Servlet API. Its helpers pass an `HttpServletRequest` to RevetSec core as raw input, and write RevetSec results to an `HttpServletResponse`. They contain no protocol logic, and every validation decision is made by RevetSec core.

This adapter is for the `jakarta.servlet` API. For the legacy `javax.servlet` API, use [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax). The two adapters are maintained as twins, with the same class names in different packages.

The helpers are planned as static classes. These names come from RevetSec's planned API and may change before the classes exist:

- `ServletOAuth`: the authorization response of an OAuth or OpenID Connect callback, from a GET query or a POST form, and redirect responses
- `ServletBearer`: a request's bearer token, for resource servers
- `ServletSaml`: the message of a SAML HTTP-POST binding request, and the redirect or auto-submitting form response that sends one
- `ServletScim`: a SCIM request's query, body and precondition headers, and the response for a SCIM result

### Installation

Adapter 1.x requires RevetSec core 1.0.0 or later. JDK 17 or newer is required, with a minimum runtime of Java 17.0.3.

RevetSec core and the Servlet API are `provided` dependencies of this adapter, so your application declares all three coordinates below. The adapter is compiled against `jakarta.servlet-api` 6.1.0 (Servlet 6.1). At runtime the Servlet API comes from your servlet container, so declare it `provided` (Maven) or `compileOnly` (Gradle).

**Nothing has been published yet, including snapshots.** Until the first release, install RevetSec core and then this adapter into your local Maven repository from their source checkouts:

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

### Status

This adapter is **pre-release**, like RevetSec core. The repository currently holds the build, contract tests and CI configuration (milestone M0). Its helpers are written after the core APIs they call.

RevetSec has not been independently audited. That includes this adapter. Its security evidence is meant to be reproducible by anyone and will be listed in the [`docs/`](https://github.com/revetsec/revetsec/tree/main/docs) directory of the core repository as it is produced. None of it exists yet.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Development Verification

This adapter builds against RevetSec core from source. With `JAVA_HOME` pointing at JDK 17 or newer, and the core repository checked out next to this one:

```shell
$ mvn -B -ntp -f ../revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
$ python3 scripts/verify-core-drift.py --core-directory ../revetsec
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists every check that CI runs, and explains how CI pins the core commit it builds against.

### License

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
