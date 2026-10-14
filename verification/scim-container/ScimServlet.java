/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package example;

import com.revetsec.json.*;
import com.revetsec.scim.*;
import com.revetsec.servlet.jakarta.ServletScim;
import com.revetsec.servlet.jakarta.ServletScimBodyResult;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

/** Executable test-only in-memory host for paired transport qualification; never deploy this store. */
public final class ScimServlet extends HttpServlet {
    private final ScimResourceType users = ScimResourceType.userInstance();
    private final ScimResourceType groups = ScimResourceType.groupInstance();
    private final ScimServiceProvider provider = ScimServiceProvider.builder()
            .baseUri(URI.create("https://example.test/scim/"))
            .resourceTypes(List.of(users, groups))
            .limits(ScimLimits.builder().maximumBodyBytes(16_384).build())
            .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build())
            .stringMatching((path, definition, operator, value, literal) -> switch (operator) {
                case EQ -> ScimStringMatchResult.fromMatched(value.equals(literal));
                case NE -> ScimStringMatchResult.fromMatched(!value.equals(literal));
                default -> ScimStringMatchResult.unsupportedInstance();
            }).build();
    private final Map<String, ScimResource> rows = new LinkedHashMap<>();
    private final ReentrantLock transaction = new ReentrantLock();
    private long sequence;
    private static final Instant TIME = Instant.parse("2026-10-13T00:00:00Z");

    @Override protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String credential = System.getProperty("fixture.credential");
        List<String> headers = Collections.list(request.getHeaders("Authorization"));
        if (credential == null || !headers.equals(List.of("Bearer " + credential))) {
            response.setHeader("WWW-Authenticate", "Bearer realm=\"scim\"");
            write(response, provider.errorResponse(ScimError.unauthenticatedInstance())); return;
        }
        String path = request.getPathInfo();
        if ("/ServiceProviderConfig".equals(path) && "GET".equals(request.getMethod())) {
            write(response, prepared(provider.serviceProviderConfigResponseResult(rawQuery(request)))); return;
        }
        String[] segments = path == null ? new String[0] : path.split("/", -1);
        if (segments.length < 2 || segments.length > 3) { fail(response, ScimError.notFoundInstance()); return; }
        ScimResourceType type = "Users".equals(segments[1]) ? users : "Groups".equals(segments[1]) ? groups : null;
        if (type == null) { fail(response, ScimError.notFoundInstance()); return; }
        boolean collection = segments.length == 2;
        String key = collection ? "" : type.getName() + "/" + segments[2];
        String method = request.getMethod();
        ScimAttributeSelectionResult selectionResult = ServletScim.attributeSelectionResultFor(provider, type, request);
        if (!(selectionResult instanceof ScimAttributeSelectionResult.Succeeded selected)) {
            fail(response, ((ScimAttributeSelectionResult.Rejected) selectionResult).getError()); return;
        }
        List<String> contentTypes = ServletScim.contentTypeHeaderValuesFor(request);
        byte[] body = new byte[0];
        if (Set.of("POST", "PUT", "PATCH").contains(method)) {
            ServletScimBodyResult read = ServletScim.bodyResultFor(provider, request);
            if (read instanceof ServletScimBodyResult.Read available) body = available.getBodyWithPersonalData();
            else if (read instanceof ServletScimBodyResult.Rejected rejected) { fail(response, rejected.getError()); return; }
            else { fail(response, ScimError.unavailableInstance()); return; }
        }
        ScimResponse prepared;
        transaction.lock();
        try {
            ScimResource current = rows.get(key);
            if (!collection && current == null) { prepared = provider.errorResponse(ScimError.notFoundInstance()); }
            else if (collection && "GET".equals(method)) {
                ScimQueryParseResult parsed = ServletScim.queryResultFor(provider, type, request);
                if (parsed instanceof ScimQueryParseResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                else {
                    ScimQuery query = ((ScimQueryParseResult.Succeeded) parsed).getQuery();
                    // This small transport fixture has no query backend; fail unsupported execution honestly.
                    if (query.getFilter().isPresent() || query.getSortBy().isPresent()) prepared = provider.errorResponse(ScimError.notImplementedInstance());
                    else {
                        List<ScimResource> all = rows.values().stream().filter(row -> row.getResourceType() == type).toList();
                        int start = (int) Math.min(all.size(), query.getStartIndex().orElseThrow() - 1);
                        List<ScimResource> page = all.subList(start, Math.min(all.size(), start + query.getCount()));
                        prepared = prepared(provider.listResponseResult(ScimListPage.withQuery(query).resources(page).totalResults((long) all.size()).build()));
                    }
                }
            } else if (!collection && "GET".equals(method)) {
                ScimIfNoneMatchResult conditional = ServletScim.ifNoneMatchResultFor(provider, current, request);
                if (conditional instanceof ScimIfNoneMatchResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                else if (conditional instanceof ScimIfNoneMatchResult.NotModified) prepared = prepared(provider.notModifiedResponseResult(current));
                else prepared = prepared(provider.resourceResponseResult(current, selected.getAttributeSelection()));
            } else if (collection && "POST".equals(method)) {
                ScimResourceParseResult parsed = provider.parseResourceResult(type, contentTypes, body);
                if (parsed instanceof ScimResourceParseResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                else if (rows.size() >= 16) prepared = provider.errorResponse(ScimError.unavailableInstance());
                else {
                    ScimResourceParseResult.Succeeded success = (ScimResourceParseResult.Succeeded) parsed;
                    String id = "r" + (sequence + 1);
                    ScimResource candidate = metadata(success.getResource(), id, sequence + 1);
                    ScimResponseResult output = provider.createdResponseResult(candidate, success.getSuppliedAttributePaths(), selected.getAttributeSelection());
                    if (output instanceof ScimResponseResult.Prepared ready) {
                        // The authenticated fixture is the only tenant/caller. A real host enforces permissions,
                        // uniqueness and membership integrity here, before durable resource+member commit.
                        rows.put(type.getName() + "/" + id, candidate); ++sequence; prepared = ready.getResponse();
                    } else prepared = provider.errorResponse(((ScimResponseResult.Rejected) output).getError());
                }
            } else if (!collection && Set.of("PUT", "PATCH", "DELETE").contains(method)) {
                ScimIfMatchResult conditional = ServletScim.ifMatchResultFor(provider, current, request);
                if (conditional instanceof ScimIfMatchResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                else if ("DELETE".equals(method)) { prepared = provider.noContentResponse(); rows.remove(key); }
                else if ("PUT".equals(method)) {
                    ScimResourceParseResult parsed = provider.parseReplacementResult(type, current, contentTypes, body);
                    if (parsed instanceof ScimResourceParseResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                    else {
                        ScimResourceParseResult.Succeeded success = (ScimResourceParseResult.Succeeded) parsed;
                        ScimResource candidate = metadata(success.getResource(), current.getId().orElseThrow(), sequence + 1);
                        ScimResponseResult output = provider.replacementResponseResult(candidate, success.getSuppliedAttributePaths(), selected.getAttributeSelection());
                        if (output instanceof ScimResponseResult.Prepared ready) { rows.put(key, candidate); ++sequence; prepared = ready.getResponse(); }
                        else prepared = provider.errorResponse(((ScimResponseResult.Rejected) output).getError());
                    }
                } else {
                    ScimPatchParseResult parsed = provider.parsePatchRequestResult(type, contentTypes, body);
                    if (parsed instanceof ScimPatchParseResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                    else {
                        ScimPatchApplicationResult applied = provider.applyPatchResult(current, ((ScimPatchParseResult.Succeeded) parsed).getPatchRequest());
                        if (applied instanceof ScimPatchApplicationResult.Rejected rejected) prepared = provider.errorResponse(rejected.getError());
                        else {
                            ScimPatchResult change = ((ScimPatchApplicationResult.Succeeded) applied).getPatchResult();
                            // Authorize requested paths even for a no-op, then effective paths/values. This fixture's
                            // sole authenticated caller is permitted every schema-writable path; production must
                            // implement tenant policy before this response preparation and storage boundary.
                            ScimResource candidate = change.isModified() ? metadata(change.getResource(), current.getId().orElseThrow(), sequence + 1) : current;
                            ScimResponseResult output = provider.patchResponseResult(candidate, change.getSuppliedAttributePaths(), selected.getAttributeSelection());
                            if (output instanceof ScimResponseResult.Prepared ready) {
                                if (change.isModified()) { rows.put(key, candidate); ++sequence; }
                                prepared = ready.getResponse();
                            } else prepared = provider.errorResponse(((ScimResponseResult.Rejected) output).getError());
                        }
                    }
                }
            } else {
                response.setHeader("Allow", collection ? "GET, POST" : "GET, PUT, PATCH, DELETE");
                prepared = provider.errorResponse(ScimError.methodNotAllowedInstance());
            }
        } finally { transaction.unlock(); }
        // Only a confirmed fixture commit reaches a success response; durable unknown-commit outcomes need
        // a separate application branch, as described in the paired cookbook and core provisioning example.
        write(response, prepared);
    }

    private ScimResource metadata(ScimResource candidate, String id, long version) {
        Map<String, JsonValue> document = new LinkedHashMap<>(candidate.getDocument().getMembers());
        document.put("id", JsonString.fromValue(id));
        document.put("meta", JsonObject.builder().put("resourceType", candidate.getResourceType().getName())
                .put("created", TIME.toString()).put("lastModified", TIME.plusSeconds(version).toString())
                .put("location", provider.resourceLocationFor(candidate.getResourceType(), id).toASCIIString())
                .put("version", "\"" + version + "\"").build());
        return candidate.copy().document(JsonObject.fromMembers(document)).finish();
    }
    private ScimResponse prepared(ScimResponseResult result) {
        if (result instanceof ScimResponseResult.Prepared ready) return ready.getResponse();
        return provider.errorResponse(((ScimResponseResult.Rejected) result).getError());
    }
    private void fail(HttpServletResponse response, ScimError error) throws IOException { write(response, provider.errorResponse(error)); }
    private static void write(HttpServletResponse response, ScimResponse prepared) throws IOException { ServletScim.writeResponse(response, prepared); }
    private static String rawQuery(HttpServletRequest request) { return request.getQueryString() == null ? "" : request.getQueryString(); }
}
