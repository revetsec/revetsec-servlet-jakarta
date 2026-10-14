# SCIM Servlet integration

`ServletScim` is a transport bridge for application-routed SCIM endpoints. The application chooses the authenticated caller, tenant, registered resource type, HTTP method and storage transaction. Core handles schema binding, protocol policy, bounded parsing, PATCH transformation, conditional headers, projection and response preparation.

Read the untouched query and original physical headers. Acquire the body once before calling Servlet parameter APIs or a framework JSON mapper. The provider's `maximumBodyBytes` bounds this read: an over-limit stream reads at most cap + 1 bytes and yields `ServletScimBodyResult.Rejected` with `requestTooLarge`. It never becomes an empty body. `Read.getBodyWithPersonalData()` returns a defensive copy. `Unavailable` means I/O failure or interrupted input, without partial bytes; an interrupted thread keeps its interrupt flag. Choose a transport failure response for unavailable input instead of passing empty bytes to core. A socket timeout is unavailable input and does not set an interrupt flag on its own.

`contentTypeHeaderValuesFor(request)` returns a request-scoped lazy list of original occurrences. It stops at the second occurrence because core rejects physical duplicates. Conditional helpers similarly stop after the configured maximum occurrence count plus one; core rejects that excess. Neither helper joins or splits fields. If a trusted edge/container collapses forbidden physical duplicates, reject those at the edge before they lose their representation.

The compiled [paired Servlet example](../verification/scim-container/ScimServlet.java) shows direct header-aware create/PUT/PATCH calls after the body result branches, unchanged query/projection helpers, conditional checks, and exact prepared responses. Its in-memory store and single disposable test credential are only a qualification fixture; they are not a production provisioning backend. Its deliberately limited query backend rejects filters and sorting rather than advertising or faking unsupported execution.

For a production write, use this ordering:

1. Authenticate and resolve the tenant; parse body, PATCH and projection with explicit result branches.
2. Begin a tenant-scoped transaction, load the current resource and members under a lock or version predicate, and handle missing resources.
3. Check `If-Match` against that exact resource. Apply PATCH or the membership reducer, keeping full-evaluation fallback inside the same transaction.
4. Authorize attempted paths even for a no-op, then effective paths/values and privilege changes. Enforce uniqueness and member-reference integrity.
5. Calculate the actual change and assign authoritative metadata only when changed. Preserve the existing version for a no-op.
6. Prepare the bounded final response before commit. A rejected preparation rolls back the candidate.
7. Persist resources and membership atomically, distinguish conflicts, outages and unknown commits, and emit only after confirmed commit. Do not automatically replay an unknown commit.

Use the same preparation/persistence boundary for create, PUT and delete. Core's provisioning guide and durable example document host-owned transaction branches. `ServletScim.writeResponse(response, prepared)` preserves status, header values and bytes without JSON marshalling, URL rewriting, flushing or closing streams. Its output `IOException` stays a transport exception. The application suppresses body writes for HEAD and owns any host-level headers. Set an appropriate `WWW-Authenticate` challenge on a host-generated 401 and an `Allow` list for the actual target route on a 405 before calling `writeResponse`; the emitter preserves those fields. The paired example shows the authentication challenge and distinct collection/resource method lists. Bound host-added headers under the transport limits as well.

Set corresponding trusted-edge and container allocation/time limits. The paired runner uses Tomcat `maxHttpRequestHeaderSize=16384`, `maxHeaderCount=128`, `maxParameterCount=64`, `connectionTimeout=2000`, `maxConnections=16`, `maxThreads=4`, `maxPostSize=16384` and `maxSwallowSize=16384`, plus a provider body cap of 16384 bytes. Tomcat's `maxPostSize` limits form processing, not arbitrary SCIM JSON buffering; keep SCIM on raw streaming input and set an actual body cap at the trusted edge. The Servlet adapter neither installs routes nor configures its container.

## Real-container qualification

[run.py](../verification/scim-container/run.py) compiles the paired example for Java 17, deploys it in a private Tomcat instance bound to `127.0.0.1`, and tests actual User and Group create/GET/PUT/PATCH/delete flows. It also tests Group membership, explicit PATCH projection, no-op versions, late-operation atomic rejection, 304/412, untouched query multiplicity, physical Content-Type duplicates, malformed UTF-8, body overflow and authentication rejection. This is transport and example qualification, not independent-client interoperability or durable database qualification.

[runtime.json](../verification/scim-container/runtime.json) pins Tomcat 11.0.27 under Apache-2.0 with the official SHA-512 archive digest, release and advisory sources checked on 2026-10-13. The runner verifies the digest before extraction, records exact source/JAR/runtime identities and bounded check names, and removes its process and private instance after success or failure. It retains no credentials, bodies or runtime logs. Refresh reviewed pins explicitly; never replace the checksum with a downloaded unchecked value.

Build core and the adapter first, then run with the exact built artifacts:

```shell
python3 verification/scim-container/run.py \
  --tomcat-archive /private/tmp/apache-tomcat-11.0.27.tar.gz \
  --core-jar ../revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --adapter-jar target/revetsec-servlet-jakarta-1.0.0-SNAPSHOT.jar \
  --java-home "$JAVA_HOME" \
  --output /private/tmp/revetsec-scim-jakarta-evidence
```

The Jakarta and javax examples, runner and API signatures are paired; only Servlet imports, package names and the reviewed Tomcat runtime differ. Both adapter artifacts keep every production dependency `provided`; the concrete Soklet Servlet request/response implementations used by unit tests stay test scope.
