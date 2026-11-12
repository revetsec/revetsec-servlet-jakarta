# Complete S1 OIDC RP host qualification

This directory runs [the paired application recipe](../../docs/oidc-rp.md) in its
reviewed disposable Tomcat. Supply explicit selected core/adapter SHA256 values.
`run.py` executes one positive matrix; `calibrate.py` requires its green control
before four private application-host defects. Only exact named assertions after
readiness and successful process/instance cleanup count as detection.

Synthetic OP, token/JWKS, signing, account, clock and fault controls are test-only.
Actual public OIDC/Servlet APIs and HTTP routing are exercised. The private form
driver and fixed secure loopback flag do not establish a real browser, OP account,
TLS handshake, deployment recovery or formal manual S1 tool pass. Fixture-only
explicit interrupt clearing follows recorded pre-clear state/output observations;
it does not change production-handler interruption semantics.
