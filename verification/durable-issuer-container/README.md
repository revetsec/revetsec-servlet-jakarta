# Servlet issuer with disposable PostgreSQL

This optional qualifier composes the existing [durable backend recipe](../../docs/ServletDurableBackendRecipe.java), [workflow helpers](../../docs/ServletWorkflowRecipes.java), packaged unpublished PostgreSQL reference store and actual Servlet issuer/bearer APIs. The fixed synthetic account and private fixture controls are test infrastructure. It installs no production route, identity system, database or recovery controller. The ordinary adapter build does not launch this workload.

The runner accepts reviewed Tomcat9/11 archives and explicit SHA256 selections for the core, namespace adapter, reference-store, Pyranid and PostgreSQL driver JARs. Every mismatch is rejected before output or resource creation. It uses only the pinned cached PostgreSQL image, a new owned container/network/volume, ephemeral loopback ports, fresh schema and a restricted runtime role. There is no external database URL option. Actual loaded JAR origins/hashes are checked before the fixture constructs the issuer or opens connections. Source, schema and reviewed runtime pins are hashed and must stay unchanged.

```sh
python3 -B verification/durable-issuer-container/run.py \
  --tomcat-archive /absolute/reviewed-tomcat.tar.gz \
  --core-jar /absolute/core.jar --core-sha256 EXACT_CORE_SHA256 \
  --adapter-jar /absolute/adapter.jar --adapter-sha256 EXACT_ADAPTER_SHA256 \
  --store-jar /absolute/reference-stores.jar --store-sha256 EXACT_STORE_SHA256 \
  --pyranid-jar /absolute/pyranid-4.7.0.jar --pyranid-sha256 EXACT_PYRANID_SHA256 \
  --driver-jar /absolute/postgresql-42.7.14.jar --driver-sha256 EXACT_DRIVER_SHA256 \
  --checker-qual-jar /absolute/checker-qual-3.55.1.jar \
  --java-home /absolute/jdk21 --annotations-repository /absolute/maven-repository \
  --output /private/tmp/fresh-durable-issuer-evidence
```

The default reference sources/schema are the sibling core checkout's `examples/postgresql-pending-store`; `--reference-store-source-root` selects an exact source packet instead. `--durable-recipe-source` and `--workflow-source` allow the exact matching historical recipe sources when the workspace has advanced. `--fixture-source` and `--servlet-source` are private calibration overrides, always hashed. Select coherent artifacts and source snapshots; an old receipt does not qualify later API changes.

The normal unpublished store JAR's manifest names four relative dependency links. The qualifier supplies those exact links only in a private compilation directory, including the separately pinned checker-qual annotation JAR. It preserves the selected store JAR bytes. The running WAR contains only the five explicitly selected runtime JARs, with no manifest-link directory. Startup asserts JUnit, JSpecify and checker-qual classes are absent. Compilation is `--release 17 -Xlint:all -Werror`; the two new fixture sources receive an attributed explicit-nullability audit. The unchanged example snippets retain their own source lineage and qualification. Run supported17/21/27 separately.

The fixed issuer is `https://issuer.example/issuer`; its advertised authorization/token/JWKS URLs match the mounted `/issuer/*` routes. The Host and browser Origin are fixed separately; forwarded input never selects them.

The actual HTTP workload performs explicit synthetic-account browser bootstrap, CSRF-bound authorization and approval, S256 code redemption, protected issuer-status validation, current tenant/object/account authorization, introspection, refresh rotation and revocation. It checks published metadata/JWKS and stable public keys after an actual Tomcat/JVM restart. Browser sessions are bounded and deliberately volatile; persisted issuer grants, fences and keys survive that restart. Local browser close does not claim to revoke a grant. Code replay can return credential rejection while causing real grant revocation; the independent SQL oracle records that effect.

The independent scripted authority and worker clock are distinct inputs, fixed at2026-11-05T12:00Z with zero uncertainty for this fixture. Authority outage never falls back to worker or database time. Actual JDBC commit fault controls distinguish an exception before the real commit (UNKNOWN with no durable effect), a lost acknowledgement after the real commit (UNKNOWN with an applied effect), and a confirmed commit followed by authority loss (known committed with output withheld). The runner observes data, versions, sealed-form fingerprints and all256 quota buckets through a separate administrative oracle. It never uses a status read to rescue a response or automatically retry an unknown operation. A sustained connection outage is counted separately from commit entry; a one-shot setup/metadata probe failure is not an UNKNOWN callback.

Raw duplicate fields/media, ambient cookies and raw query delimiters are refused before store work. Complete and chunked bodies crossing the cap are rejected rather than truncated. A real slow-progress chunked request must receive a private503 near the original four-second request deadline without session allocation or database work; each new chunk must not renew that deadline. These are actual Tomcat observations, not a claim that every proxy preserves physical fields.

The workload also exercises actual key-provider outage, allocated-capacity refusal, an owned PostgreSQL container restart, durable subject/issuer fences, admission closure under the exact reference-store advisory-lock grammar, and a changed recovery generation fencing the retained old worker. It does not reactivate that changed generation or perform a full restore/migration. Restart uses explicit established mode, warmup and retained keys; no service request lazily initializes or repairs permanent roots. Runtime SQL privileges cannot change admission, capacity allocation or the permanent-root registry. Remaining budgets flow into the store and driver; request/body/output checks preserve the original request deadline. These component observations are not a hard latency or arbitrary collaborator-preemption guarantee.

Private control credentials are unlogged and required on all routes. The fixture uses a declared secure connector over plaintext loopback; this does not establish real TLS, a trusted edge or browser behavior. Receipts contain fixed routes/statuses, counts, public synthetic identities and fingerprints rather than token/cookie values, raw assertions, keys, secrets or bodies. Owned JVMs, database/network/volume, temporary keys and instances are removed on success and failure.

`test_artifact_selection.py` checks15 bad core/adapter/store/Pyranid/driver selections before resources. `calibrate.py` requires a green real-container control, then compiles exact private Servlet variants that omit object policy, omit current account policy or misclassify a store outage as invalid-token401. Only the named live runtime assertion with successful preparation and cleanup counts. It does not edit the live application or claim a general mutation score.

This is a finite current-artifact application/store/transport composition. It does not qualify CIMD+PostgreSQL, independent-host/fleet service, approved UTC/witness ownership, power loss, actual snapshot restore/reactivation, durable browser/account policy, hosted providers, formal M12 tools, deployment readiness or the final coherent all-feature release. Preserve those gates and earlier component receipts separately.
