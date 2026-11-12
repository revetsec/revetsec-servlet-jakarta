# Disposable S4 SCIM application qualification

The sibling `docs/ServletScimDirectoryRecipe.java` is the production example; `ScimDirectoryFixture.java` and `ScimDirectoryServlet.java` are private test-only collaborators/controls. Never deploy fixture controls. All network listeners are owned loopback instances and are stopped and removed. Do not point this fixture at customer/provider resources.

`run.py` requires an exact selected core/adapter SHA256 and the namespace's reviewed `verification/m12-container/runtime.json` archive identity before creating output or resources. It verifies actual loaded JAR origins and copied hashes, compiles at release17 with warnings fatal, runs the attributed nullability auditor, starts the pinned real Tomcat runtime and checks raw HTTP requests. Supply the selected artifact paths, matching JDK home, cached runtime archive, annotation repository and a fresh output directory:

```sh
python3 -B verification/scim-directory-container/run.py \
  --tomcat-archive /absolute/path/apache-tomcat-VERSION.tar.gz \
  --core-jar /absolute/path/revetsec.jar --core-sha256 EXACT_LOWERCASE_SHA256 \
  --adapter-jar /absolute/path/adapter.jar --adapter-sha256 EXACT_LOWERCASE_SHA256 \
  --java-home /absolute/path/jdk --annotations-repository /absolute/path/repository \
  --output /private/tmp/fresh-scim-directory-evidence
```

Run `main` in both namespaces on17/21/27. The main matrix includes signed token profile failures, trusted principal/tenant/SELF boundaries, requested/no-op/effective fields, real KDF/hash checks and ordinary same-local-name extension preservation, approved filter/sort/search/projection, exact preconditions, uncertain create reconciliation, capacity recovery,8/9 admission, current-policy changes during blocked credential work, exact-version writer races, stale prepared reads, Group membership/delete integrity, bounded streamed/declared bodies and interruption restoration. The timeout control must not invent caller interruption. An explicit fixture-injected interruption is cleared only after recording the production handler left it set and published no protected response or state; this does not promise an HTTP503 can always be delivered on an ordinary interrupted container thread.

Run fresh-process `--scenario expiry-write`, `expiry-read`, `rollback`, `keys-outage` and `small-response`. The expiry injections sample exactly token expiry with zero JWT skew after preparation. The key-outage branch asserts actual key HTTP flight1→2; it cannot take fault-cause credit from refresh admission holdback. The small-response branch refuses before either a new resource or hash is published. Source/startup preparation failures are preserved separately and are not core security defect detection credit.

`calibrate.py` first requires a green control, then creates private source copies with six exact single-purpose defects: SELF owner bypass, forbidden requested no-op allowance, missing exact snapshot comparison, retained primary plaintext, UNKNOWN reported as success, and missing final current policy comparison. Each must compile, reach its named live-container regression and clean its resources; an unrelated compile/setup failure does not count. Live cookbook source is never modified by calibration.

```sh
python3 -B -m unittest discover -s verification/scim-directory-container -p test_artifact_selection.py -v
python3 -B verification/scim-directory-container/calibrate.py [the same required artifact/runtime/JDK arguments] --output /private/tmp/fresh-calibration
```

Logs and receipts retain only redacted observations, safe counts and body/query hashes. Fixture tokens/passwords are never printed. The fixture's `secure=true` HTTP connector and synthetic fixed-clock identities are not realTLS, browser, hosted-provider, durable directory, full formal M12 or final all-feature qualification. Preserve exact historical receipts; select and requalify any later merged candidate separately.
