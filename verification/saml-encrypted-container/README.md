# Encrypted SAML application qualification

This optional qualifier uses the existing SAML service provider (SP) [application recipe](../../docs/saml-sp.md) and [test Servlet](../saml-sp-container/SamlSpServlet.java) unchanged. Its separate synthetic identity provider (IdP) fixture supplies a real `SamlCredential` decryption key to the recipe's existing provider factory. This is a test-only positive encrypted flow, not another deployment route or a new core API. Normal application and adapter builds do not run it.

The fixture signs the Assertion, encrypts its exact XML with AES256-GCM (12-byte IV, 128-bit tag), wraps the content key using RSA-OAEP with explicit SHA256 and MGF1-SHA256, then signs the Response. JCA separately unwraps/decrypts and compares plaintext bytes, verifies inner and outer signatures, and checks that tag/ciphertext and recipient-key mutations really fail. A genuinely signed encrypted Assertion may also succeed without a Response signature under this selected profile; `requireSignedAssertions(true)` remains enforced. Encryption is not an identity signature.

```sh
python3 -B verification/saml-encrypted-container/run.py \
  --tomcat-archive /absolute/reviewed-tomcat.tar.gz \
  --core-jar /absolute/core.jar --core-sha256 EXACT_LOWERCASE_SHA256 \
  --adapter-jar /absolute/namespace-adapter.jar --adapter-sha256 EXACT_LOWERCASE_SHA256 \
  --java-home /absolute/jdk21 --annotations-repository /absolute/maven-repository \
  --output /private/tmp/fresh-encrypted-saml-evidence
```

The default encryption key/certificate are the core's public disposable `src/test/resources/fixtures/keys/sp-encryption-rsa-2048-{key,cert}.pem` fixtures. `--encryption-key` and `--encryption-certificate` select explicit trusted test files if this checkout layout differs. Their exact digests are included with recipe, Servlet, fixture, runtime pins, auditor and runner inputs. The key is copied to an owned private file outside the WAR and removed with the instance. Never use customer credentials. Before creating outputs or listeners, the runner rejects a mismatched selected JAR or reviewed Tomcat archive. Actual loaded core/adapter origins are checked before construction. JUnit and nullability annotations are absent from the running application.

Each namespace uses its reviewed Tomcat 9/11 archive, strict `--release 17 -Xlint:all -Werror`, attributed explicit nullability, and a fresh owned loopback JVM. Synthetic time is fixed at 2026-11-05T12:00Z with zero skew; source hashes and cleanup are mandatory. Run JDK 17, 21 and 27 separately. A connector configured `secure=true` over plaintext loopback is an application fixture declaration, not a TLS handshake or browser result.

The focused matrix exercises both trusted IdPs and Redirect/POST AuthnRequest delivery, a genuine encrypted login, consumed pending state, current account authorization, session rotation, protected tenant/object access, local logout and replay. Hostile controls cover wrong recipient key, GCM tag/ciphertext, declared cipher/key algorithms, inner/outer signature and signed semantic mutations; outer signatures remain valid for encryption and inner-signature negatives. It also checks raw duplicate fields/query-form confusion/body bounds, saved provider binding, auxiliary null Origin, current account generation, exact assertion expiry after account work, logout during account lookup and during authorization. Refusals release no new application session or protected data. The original assertion and pending expiry remain authoritative after collaborators.

`calibrate.py` requires a green actual container control, then tests three exact private recipe copies: omitted decryption credentials, missing final current-session predicate, and inclusive assertion expiry. It accepts only the named runtime assertion with successful compilation and owned cleanup; preparation failures/timeouts do not count. The live recipe is never modified. `test_artifact_selection.py` checks five bad selection variants before resource creation.

Receipts retain fixed labels, counts, status codes and hashes rather than cookies, XML, keys or credentials. All fixtures and keys are test-only. These results do not qualify hosted-provider encryption interoperability, every supported XML Encryption shape/key rotation, browser/TLS/raw physical-header preservation, distributed/durable state, an approved UTC time source, a complete Burp/SAML Raider/ZAP exercise or a final release artifact. The SAML SP harness's malformed-encryption case remains a separate negative check; this harness adds an actual configured positive encrypted flow.
