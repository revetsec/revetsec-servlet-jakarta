# M12 adapter regression calibration

`run.py` executes the positive OAuth, bearer, issuer and WebAuthn workload in the pinned Tomcat runtime. `calibrate.py` additionally requires a compiler control and eight planted adapter defects to be detected. CI uses calibration; standalone positive runs remain available.

| Plant | Required assertion |
| --- | --- |
| OAuth redirect changes no-store to public | oauth-redirect-policy |
| OAuth callback query decoded twice | oauth-raw-query |
| Bearer parser keeps only the first occurrence | bearer-physical-duplicates |
| Issuer redirect status changed from 303 to 200 | issuer-approved-redirect |
| WebAuthn options change no-store to public | webauthn-registration-start |
| WebAuthn adapter size guard removed | adapter-webauthn-body-cap-plus-one |
| WebAuthn adapter POST guard removed | adapter-webauthn-body-method |
| Issuer header-name overflow throws again | adapter-issuer-header-name-overflow |

The positive control rebuilds all adapter production classes with release 17, parameters/debug metadata and warnings fatal. Its API and class set must match the supplied JAR. Each mutant uses the same compiler/inputs; only its target class (including any nested classes) may differ from that control. Patches exist solely in disposable copies. The live checkout and supplied JAR are not changed.

A mutant counts only when the child exits 1 at its exact named assertion after container readiness, with stable inputs and confirmed process/private-instance cleanup. A zero-exit survivor is a failure of calibration. Build/start errors, timeouts, absent receipts, wrong assertions and cleanup failures never count as detection. Private process groups receive bounded termination on timeout. These cases calibrate selected observable boundaries; they are not complete mutation, protocol, storage or release qualification.

Private adapter-only probes are deliberate: later core validation or an application method guard can mask a broken transport helper. `/wa/test/body` returns only Read plus an untrusted byte count, Rejected or Unavailable under the fixture credential; it never calls a proof-producing operation. Existing end-to-end proof/replay/commit-outcome checks still run. The issuer probe sends enough small distinct fields for the adapter cutoff while staying below the pinned container's configured count/byte limits, and requires exact private core JSON rather than any HTTP 400.

Use the arguments documented in [the workflow guide](../../docs/workflows.md), a new output directory, the exact checksum-pinned archive, JDK 21 and the pinned annotation JARs from the local Maven cache. The selected CI/local profile is POSIX, with loopback-only disposable instances. Run `python3 -m unittest discover -s verification/m12-container -p 'test_*.py'` for classifier/plant/source guards. Python optimization is refused because it removes assertions.

Reports bind sources, compiler control, changed classfiles, core/adapter/runtime hashes and named checks. They retain no request/response credentials, bodies or container logs. Private signing/authentication state, instance directories and mutated JARs are removed. Shared-clock deployment inventory, UTC/witness/restore, real browser/provider qualification and broader M12/release acceptance remain separate.
