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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.server.OAuthServerResponse;
import com.revetsec.webauthn.InMemoryWebAuthnStore;
import com.revetsec.webauthn.WebAuthnAuthenticationRequestResult;
import com.revetsec.webauthn.WebAuthnBrowserRequest;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.revetsec.webauthn.WebAuthnSettings;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Focused raw transport tests; the paired runners exercise actual Servlet containers. */
final class ServletM12TransportTests {
    @Test void oauthCallbackUsesRawQueryAndOriginalPostBody() throws Exception {
        var get = parsed(ServletOAuth.authorizationResponseResultFor(request("GET", "code=a%2Bb&state=abc", Map.of(),
                new CountingStream(0, null))));
        assertEquals("a+b", get.getCode().orElseThrow());
        assertEquals("abc", get.getState().orElseThrow());

        byte[] body = "code=from%2Bbody&state=pending".getBytes(StandardCharsets.US_ASCII);
        var post = parsed(ServletOAuth.authorizationResponseResultFor(request("POST", "tenant=one",
                Map.of("Content-Type", List.of("application/x-www-form-urlencoded")), stream(body))));
        assertEquals("from+body", post.getCode().orElseThrow());
        assertEquals("pending", post.getState().orElseThrow());
        assertEquals(List.of("one"), post.getParameters().get("tenant"));

        assertInstanceOf(ServletOAuthCallbackResult.Rejected.class, ServletOAuth.authorizationResponseResultFor(request("POST", null,
                Map.of("Content-Type", List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded")),
                stream(body))));
        assertInstanceOf(ServletOAuthCallbackResult.Rejected.class, ServletOAuth.authorizationResponseResultFor(request("GET",
                "state=a&state=b", Map.of(), new CountingStream(0, null))));
        assertThrows(IllegalArgumentException.class, () -> parsed(ServletOAuth.authorizationResponseResultFor(request("PUT", null,
                Map.of(), new CountingStream(0, null)))));
    }

    @Test void oauthCallbackReadStopsAtOneOverflowByte() throws IOException {
        CountingStream input = new CountingStream(100_000, null);
        assertInstanceOf(ServletOAuthCallbackResult.TooLarge.class, ServletOAuth.authorizationResponseResultFor(request("POST", null,
                Map.of("Content-Type", List.of("application/x-www-form-urlencoded")), input)));
        assertEquals(32_769, input.read);
        assertFalse(input.closed);
    }

    @Test void bearerRetainsPhysicalDuplicatesAndRedirectDoesNotRewrite() throws Exception {
        assertInstanceOf(BearerTokenResult.Absent.class, ServletBearer.bearerTokenResultFor(
                request("GET", null, Map.of(), new CountingStream(0, null))));
        assertInstanceOf(BearerTokenResult.Present.class, ServletBearer.bearerTokenResultFor(
                request("GET", null, Map.of("Authorization", List.of("Bearer abc")), new CountingStream(0, null))));
        assertInstanceOf(BearerTokenResult.Malformed.class, ServletBearer.bearerTokenResultFor(
                request("GET", null, Map.of("Authorization", List.of("Bearer abc", "Bearer abc")),
                        new CountingStream(0, null))));
        HttpServletRequest unavailableHeaders = (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, called, arguments) -> {
                    if ("getHeaders".equals(called.getName())) return null;
                    throw new UnsupportedOperationException(called.getName());
                });
        assertThrows(IllegalStateException.class, () -> ServletBearer.bearerTokenResultFor(unavailableHeaders));

        CapturedResponse outbound = new CapturedResponse();
        ServletOAuth.writeRedirect(outbound.response(), URI.create("https://provider.example/authorize?state=a%2Bb"));
        assertEquals(302, outbound.status);
        assertEquals(List.of("https://provider.example/authorize?state=a%2Bb"), outbound.headers.get("Location"));
        assertEquals(List.of("no-store"), outbound.headers.get("Cache-Control"));
        assertThrows(IllegalArgumentException.class, () -> ServletOAuth.writeRedirect(outbound.response(),
                URI.create("https://user@provider.example/authorize")));
    }

    @Test void issuerHeadersKeepOccurrencesAndResponseKeepsCredentialLocation() throws Exception {
        HttpServletRequest inbound = request("POST", null,
                Map.of("Content-Type", List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"),
                        "Authorization", List.of("Basic one", "Basic two")), new CountingStream(0, null));
        Method headersFor = ServletOAuthAuthorizationServer.class.getDeclaredMethod("headersFor", HttpServletRequest.class);
        headersFor.setAccessible(true);
        @SuppressWarnings("unchecked") Map<String, List<String>> headers =
                (Map<String, List<String>>) headersFor.invoke(null, inbound);
        assertEquals(List.of("Basic one", "Basic two"), headers.get("Authorization"));
        assertEquals(2, requireNonNull(headers.get("Content-Type")).size());
        HttpServletRequest unavailableHeaders = (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, called, arguments) -> switch (called.getName()) {
                    case "getHeaderNames" -> Collections.enumeration(List.of("Authorization"));
                    case "getHeaders" -> null;
                    default -> throw new UnsupportedOperationException(called.getName());
                });
        InvocationTargetException unavailable = assertThrows(InvocationTargetException.class,
                () -> headersFor.invoke(null, unavailableHeaders));
        assertInstanceOf(IllegalStateException.class, unavailable.getCause());
        HttpServletRequest repeatedNames = (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, called, arguments) -> switch (called.getName()) {
                    case "getHeaderNames" -> Collections.enumeration(Collections.nCopies(65, "X"));
                    case "getHeaders" -> Collections.emptyEnumeration();
                    default -> throw new UnsupportedOperationException(called.getName());
                });
        InvocationTargetException excess = assertThrows(InvocationTargetException.class,
                () -> headersFor.invoke(null, repeatedNames));
        assertInstanceOf(IllegalArgumentException.class, excess.getCause());

        Method prepare = OAuthServerResponse.class.getDeclaredMethod("prepare", int.class, Map.class,
                URI.class, byte[].class, int.class, int.class);
        prepare.setAccessible(true);
        URI destination = URI.create("https://client.example/cb?code=private&state=private");
        OAuthServerResponse prepared = (OAuthServerResponse) prepare.invoke(null, 303,
                Map.of("Cache-Control", List.of("no-store"), "Referrer-Policy", List.of("no-referrer")),
                destination, new byte[0], 4096, 4096);
        CapturedResponse outbound = new CapturedResponse();
        ServletOAuthAuthorizationServer.writeResponse(outbound.response(), prepared);
        assertEquals(303, outbound.status);
        assertEquals(List.of(destination.toASCIIString()), outbound.headers.get("Location"));
        assertEquals(List.of("no-store"), outbound.headers.get("Cache-Control"));
        assertEquals(0, outbound.body.size());

        Constructor<OAuthServerResponse> constructor = OAuthServerResponse.class.getDeclaredConstructor(
                int.class, Map.class, URI.class, byte[].class, byte[].class);
        constructor.setAccessible(true);
        OAuthServerResponse unsafe = constructor.newInstance(303, Map.of(),
                URI.create("https://client.example/cb?code=private-secret&x=%0A"), new byte[0], new byte[0]);
        CapturedResponse rejected = new CapturedResponse();
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> ServletOAuthAuthorizationServer.writeResponse(rejected.response(), unsafe));
        assertFalse(requireNonNull(failure.getMessage()).contains("private-secret"));
        assertEquals(0, rejected.status);
        assertTrue(rejected.headers.isEmpty());
    }

    @Test void webAuthnBodyRequiresJsonPostAndDoesNotReleaseOverflowOrPartialInput() {
        WebAuthnSettings settings = WebAuthnSettings.builder().maximumResponseBodyBytes(4).build();
        byte[] original = "abc".getBytes(StandardCharsets.UTF_8);
        var read = assertInstanceOf(ServletWebAuthnBodyResult.Read.class,
                ServletWebAuthn.bodyResultFor(settings, request("POST", null,
                        Map.of("Content-Type", List.of("application/json; charset=utf-8")), stream(original))));
        byte[] returned = read.getBodyWithPersonalData();
        Arrays.fill(returned, (byte) 0);
        assertArrayEquals(original, read.getBodyWithPersonalData());
        assertFalse(read.toString().contains("abc"));

        CountingStream tooLarge = new CountingStream(100, null);
        assertInstanceOf(ServletWebAuthnBodyResult.Rejected.class,
                ServletWebAuthn.bodyResultFor(settings, request("POST", null,
                        Map.of("Content-Type", List.of("application/json")), tooLarge)));
        assertEquals(5, tooLarge.read);
        assertFalse(tooLarge.closed);
        for (Map<String, List<String>> headers : List.of(Map.<String, List<String>>of(),
                Map.of("Content-Type", List.of("application/json", "application/json")),
                Map.of("Content-Type", List.of("text/plain")),
                Map.of("Content-Type", List.of("\rapplication/json")),
                Map.of("Content-Type", List.of("application/json\u000b"))))
            assertInstanceOf(ServletWebAuthnBodyResult.Rejected.class,
                    ServletWebAuthn.bodyResultFor(settings, request("POST", null, headers, stream(original))));
        assertInstanceOf(ServletWebAuthnBodyResult.Rejected.class,
                ServletWebAuthn.bodyResultFor(settings, request("GET", null,
                        Map.of("Content-Type", List.of("application/json")), stream(original))));
        assertInstanceOf(ServletWebAuthnBodyResult.Unavailable.class,
                ServletWebAuthn.bodyResultFor(settings, request("POST", null,
                        Map.of("Content-Type", List.of("application/json")),
                        new CountingStream(3, new IOException("private")))));
        try {
            assertInstanceOf(ServletWebAuthnBodyResult.Unavailable.class,
                    ServletWebAuthn.bodyResultFor(settings, request("POST", null,
                            Map.of("Content-Type", List.of("application/json")),
                            new CountingStream(3, new InterruptedIOException("private")))));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test void webAuthnWriterEmitsPreparedJsonExactly() throws Exception {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("key",
                Base64.getEncoder().encodeToString(key))).build();
        WebAuthnRecoveryGate gate = remaining -> new WebAuthnRecoveryGate.Permit() {
            @Override public boolean isCurrent() { return true; }
            @Override public void close() { }
        };
        WebAuthnRelyingParty party = WebAuthnRelyingParty.withRelyingPartyId("login.example.com")
                .relyingPartyName("Example").allowedOrigins(Set.of("https://login.example.com"))
                .credentialNamespace("tenant").store(InMemoryWebAuthnStore.withLimits(128, 2_000_000))
                .stateSealer(sealer).recoveryGate(gate).build();
        WebAuthnBrowserRequest prepared = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                party.beginAuthenticationResult(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])))
                .getRequest();
        CapturedResponse outbound = new CapturedResponse();
        ServletWebAuthn.writeBrowserRequest(outbound.response(), prepared);
        assertEquals(200, outbound.status);
        assertArrayEquals(prepared.getJson().getBytes(StandardCharsets.UTF_8), outbound.body.toByteArray());
        assertEquals(List.of("no-store"), outbound.headers.get("Cache-Control"));
        assertEquals(List.of("nosniff"), outbound.headers.get("X-Content-Type-Options"));
        assertEquals(List.of(Integer.toString(outbound.body.size())), outbound.headers.get("Content-Length"));
    }

    private static @NonNull HttpServletRequest request(@NonNull String method, @Nullable String query,
            @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers,
            @NonNull ServletInputStream stream) {
        return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, (proxy, called, arguments) -> switch (called.getName()) {
                    case "getMethod" -> method;
                    case "getQueryString" -> query;
                    case "getInputStream" -> stream;
                    case "getHeaders" -> Collections.enumeration(headers.getOrDefault((String) arguments[0], List.of()));
                    case "getHeaderNames" -> Collections.enumeration(headers.keySet());
                    default -> throw new UnsupportedOperationException(called.getName());
                });
    }

    private static @NonNull ServletInputStream stream(byte @NonNull [] bytes) {
        return new CountingStream(bytes.length, null) {
            @Override public int read() throws IOException {
                int index = this.read;
                int ignored = super.read();
                return ignored < 0 ? -1 : bytes[index] & 0xff;
            }
        };
    }

    private static class CountingStream extends ServletInputStream {
        private final int length;
        private final @Nullable IOException failure;
        int read;
        boolean closed;
        CountingStream(int length, @Nullable IOException failure) { this.length = length; this.failure = failure; }
        @Override public int read() throws IOException {
            if (this.failure != null && this.read == 1) throw this.failure;
            if (this.read == this.length) return -1;
            this.read++;
            return 'x';
        }
        @Override public void close() { this.closed = true; }
        @Override public boolean isFinished() { return this.read >= this.length; }
        @Override public boolean isReady() { return true; }
        @Override public void setReadListener(@NonNull ReadListener listener) { throw new UnsupportedOperationException(); }
    }

    private static final class CapturedResponse {
        private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers = new LinkedHashMap<>();
        private final @NonNull ByteArrayOutputStream body = new ByteArrayOutputStream();
        private int status;
        private @NonNull HttpServletResponse response() {
            ServletOutputStream output = new ServletOutputStream() {
                @Override public void write(int value) { body.write(value); }
                @Override public boolean isReady() { return true; }
                @Override public void setWriteListener(@NonNull WriteListener listener) { throw new UnsupportedOperationException(); }
            };
            return (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class}, (proxy, called, arguments) -> {
                        switch (called.getName()) {
                            case "setStatus" -> status = (Integer) arguments[0];
                            case "setHeader" -> headers.put((String) arguments[0], new ArrayList<>(List.of((String) arguments[1])));
                            case "addHeader" -> headers.computeIfAbsent((String) arguments[0], ignored -> new ArrayList<>())
                                    .add((String) arguments[1]);
                            case "setContentLength" -> headers.put("Content-Length", List.of(Integer.toString((Integer) arguments[0])));
                            case "getOutputStream" -> { return output; }
                            default -> throw new UnsupportedOperationException(called.getName());
                        }
                        return null;
                    });
        }
    }
	private static @NonNull AuthorizationResponse parsed(@NonNull ServletOAuthCallbackResult result) {
		return assertInstanceOf(ServletOAuthCallbackResult.Succeeded.class, result).getResponse();
	}

}
