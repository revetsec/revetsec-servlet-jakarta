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
package com.revetsec.servlet.jakarta;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.scim.ScimAttributeSelectionResult;
import com.revetsec.scim.ScimError;
import com.revetsec.scim.ScimIfMatchResult;
import com.revetsec.scim.ScimIfNoneMatchResult;
import com.revetsec.scim.ScimQueryParseResult;
import com.revetsec.scim.ScimResource;
import com.revetsec.scim.ScimResourceType;
import com.revetsec.scim.ScimResponse;
import com.revetsec.scim.ScimServiceProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import static java.util.Objects.requireNonNull;

/** Thin raw-input SCIM transport helpers for application-routed Servlet endpoints.
 * The application selects the caller, tenant, resource type and transaction. Acquire raw
 * headers and the body before Servlet parameter decoding; then invoke core's header-aware parser.
 * Container and trusted-edge limits must also bound upstream body/header allocation.
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletScim {
    private ServletScim() { }

    /** Parses the unchanged resource-list query without Servlet parameter decoding.
     * @param provider the configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the routed request
     * @return the core query result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimQueryParseResult queryResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull HttpServletRequest request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        String query = request.getQueryString();
        return provider.parseQueryResult(resourceType, query == null ? "" : query);
    }

    /** Parses response projection from the unchanged query.
     * @param provider the configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the routed request
     * @return the core selection result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimAttributeSelectionResult attributeSelectionResultFor(
            @NonNull ScimServiceProvider provider, @NonNull ScimResourceType resourceType,
            @NonNull HttpServletRequest request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        String query = request.getQueryString();
        return provider.parseAttributeSelectionResult(resourceType, query == null ? "" : query);
    }

    /** Checks original If-Match occurrences against the same resource used by the transaction.
     * @param provider the configured service provider
     * @param current the authoritative current resource
     * @param request the routed request
     * @return the core conditional result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimIfMatchResult ifMatchResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResource current, @NonNull HttpServletRequest request) {
        requireNonNull(provider); requireNonNull(current); requireNonNull(request);
        return provider.checkIfMatchResult(headerValues(request, "If-Match",
                provider.getLimits().getMaximumConditionalTags() + 1), current);
    }

    /** Checks original If-None-Match occurrences for application-routed GET or HEAD handling.
     * @param provider the configured service provider
     * @param current the authoritative current resource
     * @param request the routed request
     * @return the core conditional result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimIfNoneMatchResult ifNoneMatchResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResource current, @NonNull HttpServletRequest request) {
        requireNonNull(provider); requireNonNull(current); requireNonNull(request);
        return provider.checkIfNoneMatchResult(headerValues(request, "If-None-Match",
                provider.getLimits().getMaximumConditionalTags() + 1), current);
    }

    /** Returns original Content-Type occurrences, read lazily up to the rejecting second occurrence.
     * The list is scoped to this request; it never joins, splits or decodes header values.
     * @param request the routed request
     * @return the bounded original occurrences for core's header-aware body parser
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull List<@NonNull String> contentTypeHeaderValuesFor(@NonNull HttpServletRequest request) {
        return headerValues(requireNonNull(request), "Content-Type", 2);
    }

    /** Reads at most the provider's body limit plus one overflow byte without closing its stream.
     * Overflow releases no bytes. I/O failure releases no partial bytes; interrupted reads preserve
     * the interrupt flag. A thread already interrupted does not acquire the stream.
     * @param provider the configured service provider supplying the body cap
     * @param request the routed request whose body has not been consumed
     * @return unchanged bounded bytes, an explicit size rejection, or unavailable input
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ServletScimBodyResult bodyResultFor(@NonNull ScimServiceProvider provider,
            @NonNull HttpServletRequest request) {
        requireNonNull(provider); requireNonNull(request);
        if (Thread.currentThread().isInterrupted()) return ServletScimBodyResult.Unavailable.INSTANCE;
        int cap = provider.getLimits().getMaximumBodyBytes();
        try {
            byte[] bytes = request.getInputStream().readNBytes(cap + 1);
            if (Thread.currentThread().isInterrupted()) return ServletScimBodyResult.Unavailable.INSTANCE;
            return bytes.length > cap
                    ? new ServletScimBodyResult.Rejected(ScimError.requestTooLargeInstance())
                    : new ServletScimBodyResult.Read(bytes);
        } catch (InterruptedIOException failure) {
            if (!(failure instanceof SocketTimeoutException)) Thread.currentThread().interrupt();
            return ServletScimBodyResult.Unavailable.INSTANCE;
        } catch (IOException failure) {
            return ServletScimBodyResult.Unavailable.INSTANCE;
        }
    }

    /** Writes exact prepared status, physical header values and personal-data body bytes.
     * Call only after confirmed persistence for writes. No flushing, stream closing, URL rewriting
     * or JSON marshalling is performed. The application owns HEAD suppression where applicable.
     * @param response the application-owned transport response
     * @param prepared the core-prepared bounded response
     * @throws IOException if the Servlet output stream fails
     * @since 1.0.0
     */
    public static void writeResponse(@NonNull HttpServletResponse response, @NonNull ScimResponse prepared)
            throws IOException {
        requireNonNull(response); requireNonNull(prepared);
        response.setStatus(prepared.getStatusCode());
        for (Map.Entry<String, List<String>> header : prepared.getHeaders().entrySet()) {
            boolean first = true;
            for (String value : header.getValue()) {
                if (first) response.setHeader(header.getKey(), value);
                else response.addHeader(header.getKey(), value);
                first = false;
            }
        }
        byte[] bytes = prepared.toHttpBodyWithPersonalData();
        if (bytes.length != 0) response.getOutputStream().write(bytes);
    }

    private static @NonNull List<@NonNull String> headerValues(@NonNull HttpServletRequest request,
            @NonNull String name, int maximumOccurrences) {
        return new HeaderValues(request, name, maximumOccurrences);
    }

    /** A request-scoped list that stops enumeration as soon as excess occurrences guarantee rejection. */
    private static final class HeaderValues extends AbstractList<@NonNull String> {
        private final @NonNull HttpServletRequest request;
        private final @NonNull String name;
        private final int maximumOccurrences;
        private @Nullable List<@NonNull String> snapshot;
        private HeaderValues(@NonNull HttpServletRequest request, @NonNull String name, int maximumOccurrences) {
            this.request = request; this.name = name; this.maximumOccurrences = maximumOccurrences;
        }
        private @NonNull List<@NonNull String> snapshot() {
            List<String> current = snapshot;
            if (current != null) return current;
            List<String> values = new ArrayList<>();
            Enumeration<String> original = request.getHeaders(name);
            if (original != null) while (values.size() < maximumOccurrences && original.hasMoreElements())
                values.add(requireNonNull(original.nextElement()));
            current = List.copyOf(values);
            snapshot = current;
            return current;
        }
        @Override public int size() { return snapshot().size(); }
        @Override public @NonNull String get(int index) { return snapshot().get(index); }
    }
}
