# Passkey action application container checks

`run.py` compiles the new application and test-only fixture with warning-fatal Java 17 compatibility, runs the attributed nullability audit, then starts an owned disposable pinned Tomcat instance. It requires explicit core and adapter JAR paths and lowercase SHA-256 values, checks the reviewed Tomcat archive SHA-512 before creating an output/instance, verifies copied bytes, and checks actual core/adapter code origins inside the running servlet. Test and annotation JARs are excluded from runtime. Never deploy the fixture.

Run `python3 -B test_artifact_selection.py` for refusal-before-resource checks. To run the native fixture, provide a fresh output path:

```sh
python3 -B run.py --tomcat-archive /path/to/reviewed-tomcat.tar.gz \
  --core-jar /path/to/core.jar --core-sha256 SELECTED_CORE_SHA256 \
  --adapter-jar /path/to/servlet-adapter.jar --adapter-sha256 SELECTED_ADAPTER_SHA256 \
  --java-home /path/to/jdk --annotations-repository /path/to/maven/repository \
  --scenario main --output /private/tmp/new-owned-evidence
```

The selected core must include the typed `WebAuthnReauthentication` API. Runtime identity comes from `../m12-container/runtime.json`; no runtime is downloaded. Use Java 17, 21 and 27 with the matching javax/Tomcat9 or jakarta/Tomcat11 adapter. `--recipe-source` is an exact-hash recorded private calibration override, not a production selection mechanism. `calibrate.py` runs a green native control, then exact private source plants and requires each named application assertion after successful preparation and owned-resource cleanup. Compile/setup errors do not count as detection.

The `main` scenario uses actual public RP registration, sign-in, typed reauthentication, credential list/removal and JCA Ed25519 signatures from two synthetic authenticators. It exercises account/RP/namespace/purpose/ceremony/pending-object context, a different authenticating key and removal target, wrong-target consumption, one-use concurrency, separate operator authorization, raw critical-header/cookie/query/media/body refusals, and actual eight/ninth admission before store reads. A post-commit fixture delay occurs outside the backing store monitor and proves that pending replacement and local logout fence the delayed continuation. Separate writer/permit-close delays prove exact cleanup preserves newer grants. Foreign-application cleanup is tested using a genuine core proof and natural local sessions, never a fabricated proof or result.

Fresh-process scenarios are `unknown`, `reconciliation`, `capacity` and `deadline`. The first two inject legal outcome loss around a genuinely observed in-memory ceremony commit; they distinguish UNKNOWN from known-committed/final-clock refusal, withhold authority and close local admission without retry. They are not PostgreSQL acknowledgement-loss proof. Capacity refuses without evicting live sessions, then reclaims expired entries without rollback revival. Deadline tests synthetic signed-overflow arithmetic through the actual helper; they do not claim elapsed real-time or UTC qualification.

Most replies use the actual Tomcat response directly. Explicit writer controls inject synchronous I/O/runtime refusal before body publication; the recipe's cleanup is observed, with no peer-ACK inference. `close-interrupt` alone uses a bounded test-only response buffer: the fixture records that the production handler left interruption set and no grant published **before** clearing the flag and flushing. The original unbuffered case can close the Tomcat socket and is retained separately as a transport limitation. The production recipe never clears interruption and does not promise a 503 body while the thread remains interrupted.

The fixture exposes an unlogged random control credential and loopback-only listener, writes no raw credentials/proofs into receipts, and always stops/removes its owned instance. Receipts include exact source inputs, artifact identities, status/body hashes, named checks and cleanup. The connector's `scheme=https secure=true` is a trusted synthetic declaration over plaintext loopback; these checks do not qualify TLS, browser behavior, physical devices, a customer/provider service, durable PostgreSQL, distributed recovery, full profile C or the final release candidate.
