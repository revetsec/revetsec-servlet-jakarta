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
import com.revetsec.webauthn.WebAuthnBrowserRequest;
import com.revetsec.webauthn.WebAuthnSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

import static java.util.Objects.requireNonNull;

/** Raw WebAuthn browser transport. The application owns account approval, browser sessions,
 * browser binding, ceremony-ID routing, CSRF and the final sign-in decision.
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletWebAuthn {
    private ServletWebAuthn() { }

    /** Reads one bounded POST JSON completion body before Servlet parameter decoding. A method,
     * media-type or size failure releases no body bytes. Interrupted reads retain the interrupt flag.
     * @param settings the configured relying party's body limits
     * @param request application-routed browser completion request
     * @return unchanged bytes, explicit rejection or unavailable input
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ServletWebAuthnBodyResult bodyResultFor(@NonNull WebAuthnSettings settings,
            @NonNull HttpServletRequest request) {
        requireNonNull(settings); requireNonNull(request);
        if (!"POST".equals(request.getMethod()) || !jsonContentType(request))
            return ServletWebAuthnBodyResult.Rejected.INSTANCE;
        if (Thread.currentThread().isInterrupted()) return ServletWebAuthnBodyResult.Unavailable.INSTANCE;
        int cap = settings.getMaximumResponseBodyBytes();
        try {
            byte[] bytes = request.getInputStream().readNBytes(cap + 1);
            if (Thread.currentThread().isInterrupted()) return ServletWebAuthnBodyResult.Unavailable.INSTANCE;
            return bytes.length > cap ? ServletWebAuthnBodyResult.Rejected.INSTANCE
                    : new ServletWebAuthnBodyResult.Read(bytes);
        } catch (InterruptedIOException failure) {
            if (!(failure instanceof SocketTimeoutException)) Thread.currentThread().interrupt();
            return ServletWebAuthnBodyResult.Unavailable.INSTANCE;
        } catch (IOException failure) {
            return ServletWebAuthnBodyResult.Unavailable.INSTANCE;
        }
    }

    /** Writes core-prepared registration or authentication options as exact UTF-8 JSON.
     * @param response application-owned response
     * @param prepared core-prepared browser request
     * @throws IOException if the Servlet output stream fails
     * @since 1.0.0
     */
    public static void writeBrowserRequest(@NonNull HttpServletResponse response,
            @NonNull WebAuthnBrowserRequest prepared) throws IOException {
        requireNonNull(response); requireNonNull(prepared);
        byte[] body = prepared.getJson().getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Content-Type", "application/json; charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }

    private static boolean jsonContentType(@NonNull HttpServletRequest request) {
        Enumeration<String> values = request.getHeaders("Content-Type");
        if (values == null || !values.hasMoreElements()) return false;
        String field = requireNonNull(values.nextElement());
        if (values.hasMoreElements()) return false;
        if (field.length() > 128) return false;
        for (int index = 0; index < field.length(); index++) {
            char character = field.charAt(index);
            if ((character < 0x20 && character != '\t') || character > 0x7e) return false;
        }
        int start = 0;
        int end = field.length();
        while (start < end && (field.charAt(start) == ' ' || field.charAt(start) == '\t')) start++;
        while (end > start && (field.charAt(end - 1) == ' ' || field.charAt(end - 1) == '\t')) end--;
        String normalized = field.substring(start, end);
        return "application/json".equalsIgnoreCase(normalized)
                || "application/json; charset=utf-8".equalsIgnoreCase(normalized)
                || "application/json;charset=utf-8".equalsIgnoreCase(normalized);
    }
}
