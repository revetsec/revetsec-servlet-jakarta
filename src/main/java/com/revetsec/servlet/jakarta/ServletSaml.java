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
import com.revetsec.saml.SamlAuthenticationRequestResult;
import com.revetsec.saml.SamlLogoutRedirectResult;
import com.revetsec.saml.SamlLogoutResponseRedirectResult;
import com.revetsec.saml.SamlLogoutPostResult;
import com.revetsec.saml.SamlLogoutResponsePostResult;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlPostForm;
import com.revetsec.saml.SamlRedirectBindingMessage;
import com.revetsec.saml.SamlRedirectBindingParseResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Thin SAML transport helpers for application-routed Jakarta Servlet endpoints. Core performs
 * binding, signature, pending-state and replay validation; the application owns cookies,
 * sessions and IdP selection. Call these before any servlet parameter parser consumes the body.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletSaml {
    // Mirrors core's SAML POST bound: three encoded fields plus framing.
    private static final int MAXIMUM_ADAPTER_BODY_BYTES = 1_061_128;

    private ServletSaml() { }

    /**
     * Reads the original bounded POST body, all Content-Type header values, and the raw query.
     *
     * @param request application-routed ACS request
     * @return core's untrusted POST-binding parse result
     * @throws IOException if the servlet input stream fails
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull SamlPostBindingParseResult postBindingResultFor(
            @NonNull HttpServletRequest request) throws IOException {
        requireNonNull(request);
        if (!"POST".equals(request.getMethod()))
            throw new IllegalArgumentException("SAML ACS route requires POST");
        return postBindingResult(request, false);
    }

    /**
     * Reads the original bounded logout POST body, every Content-Type value and the raw query.
     * The application supplies browser-bound pending state to core when completing SP logout;
     * a pending cookie for a cross-site POST requires Secure, HttpOnly and SameSite=None.
     *
     * @param request application-routed logout POST request
     * @return core's untrusted logout POST-binding parse result
     * @throws IOException if the servlet input stream fails
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull SamlPostBindingParseResult postLogoutBindingResultFor(
            @NonNull HttpServletRequest request) throws IOException {
        requireNonNull(request);
        if (!"POST".equals(request.getMethod()))
            throw new IllegalArgumentException("SAML logout route requires POST");
        return postBindingResult(request, true);
    }

    private static @NonNull SamlPostBindingParseResult postBindingResult(
            @NonNull HttpServletRequest request, boolean logout) throws IOException {
        List<String> contentTypes = new ArrayList<>();
        Enumeration<String> values = request.getHeaders("Content-Type");
        if (values != null) while (values.hasMoreElements()) contentTypes.add(values.nextElement());
        String rawQuery = request.getQueryString();
        // Let core reject invalid framing before allocating or reading an untrusted body.
        byte[] framingProbe = { 'x' };
        SamlPostBindingParseResult framing = logout
                ? SamlPostBindingMessage.fromLogoutFormBodyResult(framingProbe, List.copyOf(contentTypes), rawQuery)
                : SamlPostBindingMessage.fromFormBodyResult(framingProbe, List.copyOf(contentTypes), rawQuery);
        if (framing instanceof SamlPostBindingParseResult.Rejected rejection
                && rejection.getReason() == SamlPostBindingParseResult.Reason.CONTENT_TYPE) return framing;
        byte[] body = request.getInputStream().readNBytes(MAXIMUM_ADAPTER_BODY_BYTES + 1);
        if (body.length > MAXIMUM_ADAPTER_BODY_BYTES) body = new byte[0];
        return logout ? SamlPostBindingMessage.fromLogoutFormBodyResult(body, List.copyOf(contentTypes),
                rawQuery) : SamlPostBindingMessage.fromFormBodyResult(body,
                List.copyOf(contentTypes), rawQuery);
    }

    /**
     * Parses the original HTTP-Redirect query octets for signed logout messages.
     *
     * @param request application-routed logout request
     * @return core's untrusted Redirect-binding parse result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull SamlRedirectBindingParseResult redirectBindingResultFor(
            @NonNull HttpServletRequest request) {
        requireNonNull(request);
        if (!"GET".equals(request.getMethod()))
            return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        String rawQuery = request.getQueryString();
        return SamlRedirectBindingMessage.fromRawQueryResult(rawQuery == null ? "" : rawQuery);
    }

    /**
     * Writes a core-prepared authentication redirect without servlet URL rewriting.
     *
     * @param response application-owned response, including any pending cookie
     * @param prepared core-prepared authentication request
     * @since 1.0.0
     */
    public static void writeAuthenticationRedirect(@NonNull HttpServletResponse response,
            SamlAuthenticationRequestResult.@NonNull Prepared prepared) {
        writeRedirect(response, requireNonNull(prepared).getRedirectUri());
    }

    /**
     * Writes a core-prepared SP logout redirect.
     *
     * @param response application-owned response
     * @param prepared core-prepared logout request
     * @since 1.0.0
     */
    public static void writeLogoutRedirect(@NonNull HttpServletResponse response,
            SamlLogoutRedirectResult.@NonNull Prepared prepared) {
        writeRedirect(response, requireNonNull(prepared).getRedirectUri());
    }

    /**
     * Writes a core-prepared answer to an IdP logout request.
     *
     * @param response application-owned response
     * @param prepared core-prepared logout response
     * @since 1.0.0
     */
    public static void writeLogoutResponseRedirect(@NonNull HttpServletResponse response,
            SamlLogoutResponseRedirectResult.@NonNull Prepared prepared) {
        writeRedirect(response, requireNonNull(prepared).getRedirectUri());
    }

    /**
     * Writes a core-prepared SP logout POST form. Set the browser-bound pending cookie and CSP
     * before delivery; a cross-site POST pending cookie requires Secure, HttpOnly and SameSite=None.
     *
     * @param response application-owned response
     * @param prepared core-prepared logout request
     * @param cspNonce application-generated CSP nonce, or null for manual submission
     * @throws IOException if the servlet output stream fails
     * @since 1.0.0
     */
    public static void writeLogoutPostForm(@NonNull HttpServletResponse response,
            SamlLogoutPostResult.@NonNull Prepared prepared, @Nullable String cspNonce) throws IOException {
        writePostForm(response, requireNonNull(prepared).getPostForm(), cspNonce);
    }

    /**
     * Writes a core-prepared POST answer to an IdP logout request. The application sets its CSP.
     *
     * @param response application-owned response
     * @param prepared core-prepared logout response
     * @param cspNonce application-generated CSP nonce, or null for manual submission
     * @throws IOException if the servlet output stream fails
     * @since 1.0.0
     */
    public static void writeLogoutResponsePostForm(@NonNull HttpServletResponse response,
            SamlLogoutResponsePostResult.@NonNull Prepared prepared, @Nullable String cspNonce)
            throws IOException {
        writePostForm(response, requireNonNull(prepared).getPostForm(), cspNonce);
    }

    private static void writeRedirect(@NonNull HttpServletResponse response, @NonNull URI destination) {
        requireNonNull(response);
        requireNonNull(destination);
        if (!"https".equalsIgnoreCase(destination.getScheme()) || destination.getHost() == null
                || destination.getRawUserInfo() != null || destination.getRawFragment() != null)
            throw new IllegalArgumentException("SAML Redirect requires an HTTPS host");
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", destination.toASCIIString());
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }

    /**
     * Writes a core-prepared POST form. The application sets its CSP and pending cookie first.
     *
     * @param response application-owned response
     * @param form core-prepared SAML authentication or logout form
     * @param cspNonce application-generated CSP nonce, or null for manual submission
     * @throws IOException if the servlet output stream fails
     * @since 1.0.0
     */
    public static void writePostForm(@NonNull HttpServletResponse response, @NonNull SamlPostForm form,
            @Nullable String cspNonce) throws IOException {
        requireNonNull(response);
        requireNonNull(form);
        byte[] body = form.toHtml(cspNonce).getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpServletResponse.SC_OK);
        for (Map.Entry<String, String> header : form.getHeaders().entrySet())
            response.setHeader(header.getKey(), header.getValue());
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
