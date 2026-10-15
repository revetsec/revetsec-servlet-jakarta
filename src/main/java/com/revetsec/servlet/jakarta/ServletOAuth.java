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
import com.revetsec.oauth.AuthorizationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static java.util.Objects.requireNonNull;

/** Raw OAuth callback and redirect transport for application-routed Servlet endpoints. Parsing
 * grants no identity; core completes the browser-bound authorization transaction.
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletOAuth {
    private static final int MAXIMUM_CALLBACK_BODY_BYTES = 32_768;

    private ServletOAuth() { }

    /** Parses the original GET query or bounded POST form without Servlet parameter decoding.
     * @param request application-routed callback request
     * @return parsed, rejected or oversized callback outcome
     * @throws IOException if the Servlet input stream fails
     * @throws IllegalArgumentException if the route uses neither GET nor POST
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ServletOAuthCallbackResult authorizationResponseResultFor(@NonNull HttpServletRequest request)
            throws IOException {
        requireNonNull(request);
        String method = request.getMethod();
        if ("GET".equals(method)) {
            String query = request.getQueryString();
            return ServletOAuthCallbackResult.fromParseResult(AuthorizationResponse.fromQueryStringResult(query == null ? "" : query));
        }
        if (!"POST".equals(method))
            throw new IllegalArgumentException("OAuth callback route must use GET or POST");
        byte[] body = request.getInputStream().readNBytes(MAXIMUM_CALLBACK_BODY_BYTES + 1);
        if (body.length > MAXIMUM_CALLBACK_BODY_BYTES) return ServletOAuthCallbackResult.fromTooLarge();
        List<String> contentTypes = new ArrayList<>(2);
        Enumeration<String> values = request.getHeaders("Content-Type");
        if (values != null) while (values.hasMoreElements() && contentTypes.size() < 2)
            contentTypes.add(requireNonNull(values.nextElement()));
        return ServletOAuthCallbackResult.fromParseResult(
                AuthorizationResponse.fromFormBodyResult(body, List.copyOf(contentTypes), request.getQueryString()));
    }

    /** Writes an application-approved absolute HTTP(S) redirect without Servlet URL rewriting.
     * The application sets any browser-bound pending cookie before writing the response.
     * @param response application-owned response
     * @param location trusted redirect destination
     * @since 1.0.0
     */
    public static void writeRedirect(@NonNull HttpServletResponse response, @NonNull URI location) {
        requireNonNull(response);
        String value = redirectLocation(requireNonNull(location));
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", value);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
    }

    static @NonNull String redirectLocation(@NonNull URI location) {
        String scheme = location.getScheme();
        if (!location.isAbsolute() || location.isOpaque() || location.getHost() == null
                || location.getHost().isEmpty() || location.getRawUserInfo() != null
                || location.getPort() < -1 || location.getPort() > 65_535
                || !("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme)))
            throw unsafeRedirect();
        String value = location.toASCIIString();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character <= 0x20 || character >= 0x7f) throw unsafeRedirect();
            if (character == '%' && index + 2 < value.length()) {
                int high = Character.digit(value.charAt(index + 1), 16);
                int low = Character.digit(value.charAt(index + 2), 16);
                int decoded = high * 16 + low;
                if (high >= 0 && low >= 0 && (decoded < 0x20 || decoded == 0x7f))
                    throw unsafeRedirect();
            }
        }
        return value;
    }

    private static @NonNull IllegalArgumentException unsafeRedirect() {
        return new IllegalArgumentException("OAuth redirect requires a safe absolute HTTP(S) URI without userinfo");
    }
}
