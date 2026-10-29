# Standalone JWKS publication

Publish the public keys used for application signatures without configuring an OAuth authorization server. The application owns the URL and supplies public keys and optional metadata; the publisher prepares the JSON document and HTTP response.

For an RS384 integration with an existing certificate chain, load the public X.509 certificates in leaf-first order and construct the publisher once:

```java
import com.revetsec.jose.JwksPublisher;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.PublishedJwk;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

// certificateChain is an application-loaded List<X509Certificate>, leaf first.
var publicKey = PublishedJwk.withPublicKey(certificateChain.get(0).getPublicKey())
    .keyId("epic-prod")
    .algorithm(JwsAlgorithm.RS384)
    .certificateChain(certificateChain)
    .build();

var publisher = JwksPublisher.withKeys(List.of(publicKey))
    .httpCacheMaxAge(Duration.ofHours(1))
    .build();
```

Only the public key is required. `keyId`, `algorithm` and `certificateChain` are optional; omitted algorithms remain unspecified. The builder derives public JWK parameters from the key, validates a supplied algorithm against its key type, and snapshots the supplied certificate chain. The leaf certificate must match the public key. A supplied chain is checked for certificate order and signatures, and a certificate's key-usage extension must permit the appropriate signing or certificate-signing use. This does not perform PKIX trust validation or certificate validity-time checks.

The published key contains `use: "sig"`. A supplied certificate chain adds `x5c` as standard-base64 DER certificates, and `x5t` and `x5t#S256` as base64url thumbprints of the leaf certificate. No private key is accepted by this API.

Supported key and algorithm combinations are:

| Public key | Optional algorithms |
| --- | --- |
| RSA | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` |
| EC P-256 | `ES256` |
| EC P-384 | `ES384` |
| EC P-521 | `ES512` |
| Ed25519 | `ED25519`, legacy `EDDSA` |

HMAC keys are not publishable because they are shared secrets. For a key without certificate metadata, use the same builder and omit `certificateChain(...)`.

## Servlet route

Map this servlet instance to the application's chosen JWKS URL, such as `/jwks`. Passing every method to the helper lets the core publisher prepare unsupported-method responses as well:

```java
import com.revetsec.jose.JwksPublisher;
import com.revetsec.servlet.jakarta.ServletJwks;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public final class JwksServlet extends HttpServlet {
    private final JwksPublisher publisher;

    public JwksServlet(JwksPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        ServletJwks.writeResponse(this.publisher, request, response);
    }
}
```

For application code that prepares the core response separately:

```java
ServletJwks.writeResponse(response, publisher.responseFor("GET"));
```

## HTTP behavior and rotation

GET returns `application/jwk-set+json`, the exact JSON body, `Content-Length`, an ETag, and public cache headers. HEAD returns GET's headers with no body. `If-None-Match` uses weak comparison and supports a list of tags or `*`; a matching GET or HEAD returns 304 with no body. Other methods receive 405 and `Allow: GET, HEAD`. The adapter preserves the prepared status, headers and body bytes.

Repeated `If-None-Match` values are combined as a comma-separated list. The combination is bounded at 8,192 characters; oversized input receives the core publisher's 400 response. Configure container or server header limits as appropriate for your application.

The default HTTP cache max-age is 60 seconds. `httpCacheMaxAge(...)` accepts whole seconds from zero through one day; passing `null` restores the default. It controls the outgoing `Cache-Control` max-age for downstream HTTP caches. It does not expire the immutable publisher snapshot or reload keys; calling `toJson()` by itself is unaffected. Select a max-age that fits your key rotation policy.

To rotate, construct a replacement publisher containing the active and retained verification keys and atomically replace the application's reference. Retain old public keys long enough for outstanding signatures and downstream caches. Key order is the supplied list order; changes to the document change its ETag.

## Real-container verification

After building core and this adapter, run the focused probe with the local Tomcat archive matching the reviewed [runtime pin](../verification/m12-container/runtime.json):

```shell
python3 verification/jwks-container/run.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --core-source ../revetsec \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-jwks-jakarta-container
```

The probe compiles the [servlet example](../verification/jwks-container/JwksServlet.java) for Java 17, publishes core's public test certificate chain with RS384, and checks actual GET, HEAD, conditional 304, repeated conditional fields, oversized-field 400 and method 405 responses. It binds only to `127.0.0.1`, stops its own container, and writes a source/JAR/runtime-bound `RESULT.json` and runtime log. No external service or private signing key is used. `--core-source` locates the public certificate fixtures in the pinned core checkout. The adapter CI workflow runs this probe with that checkout; its hosted result remains pending until this change is pushed.
