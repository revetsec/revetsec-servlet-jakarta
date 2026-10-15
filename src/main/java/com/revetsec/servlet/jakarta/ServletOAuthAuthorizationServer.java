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
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oauth.server.OAuthIntrospectionResult;
import com.revetsec.oauth.server.OAuthRevocationResult;
import com.revetsec.oauth.server.OAuthServerResponse;
import com.revetsec.oauth.server.OAuthTokenResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Thin issuer transport for application-routed Servlet requests and core-prepared responses.
 * Applications own route and issuer selection, browser sessions, authentication, consent and CSRF.
 * Read the original body before Servlet parameter decoding. Container and trusted-edge allocation
 * and time limits must also apply before this adapter is called.
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletOAuthAuthorizationServer {
    // Core's configurable issuer ingress cap cannot exceed 65,536 bytes.
    private static final int MAXIMUM_ISSUER_BODY_BYTES = 65_536;
    private static final int REJECTING_HEADER_COUNT = 65;

    private ServletOAuthAuthorizationServer() { }

    /** Admits unchanged authorization input with an independent application-held browser binding.
     * @param server configured issuer
     * @param request request on the configured authorization route
     * @param browserBinding canonical random binding retained in the protected session
     * @return core's restricted interaction or rejection
     * @throws IOException if the Servlet input stream fails
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull OAuthAuthorizationResult beginAuthorizationResultFor(
            @NonNull OAuthAuthorizationServer server, @NonNull HttpServletRequest request,
            @NonNull String browserBinding) throws IOException {
        requireNonNull(server); requireNonNull(request); requireNonNull(browserBinding);
        return server.beginAuthorizationResult(request.getMethod(), request.getQueryString(), bodyFor(request),
                headersFor(request), browserBinding);
    }

    /** Handles unchanged token form bytes and all materialized header occurrences.
     * @param server configured issuer
     * @param request request on the configured token route
     * @return core's committed response or rejection
     * @throws IOException if the Servlet input stream fails
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull OAuthTokenResult tokenResultFor(@NonNull OAuthAuthorizationServer server,
            @NonNull HttpServletRequest request) throws IOException {
        requireNonNull(server); requireNonNull(request);
        return server.tokenResult(request.getMethod(), request.getQueryString(), bodyFor(request), headersFor(request));
    }

    /** Handles unchanged revocation form bytes on its configured route.
     * @param server configured issuer
     * @param request request on the configured revocation route
     * @return core's committed response or rejection
     * @throws IOException if the Servlet input stream fails
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull OAuthRevocationResult revocationResultFor(@NonNull OAuthAuthorizationServer server,
            @NonNull HttpServletRequest request) throws IOException {
        requireNonNull(server); requireNonNull(request);
        return server.revokeResult(request.getMethod(), request.getQueryString(), bodyFor(request), headersFor(request));
    }

    /** Handles unchanged introspection form bytes without selecting caller or resource policy.
     * @param server configured issuer
     * @param request request on the configured introspection route
     * @return core's committed response or rejection
     * @throws IOException if the Servlet input stream fails
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull OAuthIntrospectionResult introspectionResultFor(
            @NonNull OAuthAuthorizationServer server, @NonNull HttpServletRequest request) throws IOException {
        requireNonNull(server); requireNonNull(request);
        return server.introspectionResult(request.getMethod(), request.getQueryString(), bodyFor(request),
                headersFor(request));
    }

    /** Emits the exact prepared status, physical headers, credential-bearing Location and body.
     * Keep this response out of diagnostics and add application-owned browser cookies at the edge.
     * @param response application-owned transport response
     * @param prepared restricted core response
     * @throws IOException if the Servlet output stream fails
     * @since 1.0.0
     */
    public static void writeResponse(@NonNull HttpServletResponse response,
            @NonNull OAuthServerResponse prepared) throws IOException {
        requireNonNull(response); requireNonNull(prepared);
        Optional<String> destination = prepared.getLocationWithCredentials().map(ServletOAuth::redirectLocation);
        response.setStatus(prepared.getStatusCode());
        for (Map.Entry<String, List<String>> header : prepared.getHeaders().entrySet()) {
            boolean first = true;
            for (String value : header.getValue()) {
                if (first) response.setHeader(header.getKey(), value);
                else response.addHeader(header.getKey(), value);
                first = false;
            }
        }
        if (destination.isPresent()) response.setHeader("Location", destination.orElseThrow());
        byte[] body = prepared.toHttpBodyWithCredentials();
        if (body.length != 0) response.getOutputStream().write(body);
    }

    private static byte @NonNull [] bodyFor(@NonNull HttpServletRequest request) throws IOException {
        return request.getInputStream().readNBytes(MAXIMUM_ISSUER_BODY_BYTES + 1);
    }

    /** Stops after enough fields to guarantee a core rejection, retaining duplicate occurrences. */
    private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headersFor(
            @NonNull HttpServletRequest request) {
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) throw new IllegalArgumentException("Servlet request headers are unavailable");
        Map<String, List<String>> fields = new LinkedHashMap<>();
        int occurrences = 0;
        int namesSeen = 0;
        while (names.hasMoreElements() && fields.size() < REJECTING_HEADER_COUNT
                && occurrences < REJECTING_HEADER_COUNT) {
            if (++namesSeen >= REJECTING_HEADER_COUNT)
                throw new IllegalArgumentException("Too many Servlet request header names");
            String name = requireNonNull(names.nextElement());
            List<String> values = fields.computeIfAbsent(name, ignored -> new ArrayList<>());
            Enumeration<String> originals = request.getHeaders(name);
            if (originals == null) throw new IllegalStateException("Servlet request headers are unavailable");
            while (originals.hasMoreElements()
                    && values.size() < REJECTING_HEADER_COUNT
                    && occurrences < REJECTING_HEADER_COUNT) {
                values.add(requireNonNull(originals.nextElement()));
                occurrences++;
            }
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        fields.forEach((name, values) -> result.put(name, List.copyOf(values)));
        return result;
    }
}
