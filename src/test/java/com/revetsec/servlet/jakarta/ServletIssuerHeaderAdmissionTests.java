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
import com.revetsec.oauth.server.*;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;

/** Public endpoint regressions for bounded Servlet header materialization and core refusal. */
final class ServletIssuerHeaderAdmissionTests {
    private enum Endpoint { AUTHORIZATION, TOKEN, REVOCATION, INTROSPECTION }
    private enum Shape { DISTINCT, EMPTY_DISTINCT, REPEATED_EMPTY, ENDLESS_EMPTY, DUPLICATE_TYPE, CASE_TYPE, VALUE_OVERFLOW }
    private record Rejection(OAuthServerException.@NonNull Reason reason, @NonNull OAuthServerResponse response) { }
    private static final String FORM = "grant_type=unknown&client_id=client&token=synthetic";
    private static final String AUTH_QUERY = "client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcb&resource=https%3A%2F%2Fresource.example.test&code_challenge="+"A".repeat(43)+"&code_challenge_method=S256";

    private static @NonNull OAuthAuthorizationServer server() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-11-03T12:00:00Z"), ZoneOffset.UTC);
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        OAuthAuthorizationServerStore store = new OAuthAuthorizationServerStore() {
            @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key, @NonNull Duration budget) { throw new AssertionError("Rejected input reached store read"); }
            @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) { throw new AssertionError("Rejected input reached store commit"); }
        };
        return OAuthAuthorizationServer.withIssuer("https://issuer.example.test")
                .authorizationEndpoint(URI.create("https://issuer.example.test/authorize"))
                .tokenEndpoint(URI.create("https://issuer.example.test/token")).jwksEndpoint(URI.create("https://issuer.example.test/jwks"))
                .revocationEndpoint(URI.create("https://issuer.example.test/revoke")).introspectionEndpoint(URI.create("https://issuer.example.test/introspect"))
                .clientRepository((id, budget) -> { throw new AssertionError("Rejected input reached client lookup"); }).store(store).clock(clock)
                .grantPolicy((context, budget) -> { throw new AssertionError("Rejected input reached grant policy"); })
                .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("test", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build())
                .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(
                        OAuthIssuerSigningKey.fromKeyPair("test", pair.getPrivate(), pair.getPublic()))
                        .generation("test").publishedAt(clock.instant().minusSeconds(120)).build()))
                .maximumRequestBodyBytes(65_536).resources(Map.of("https://resource.example.test", Set.of("read"))).build();
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> excessiveNamesRejectBeforeApplicationWorkAndStopAtTheBound() throws Exception {
        var server = server();
        return Arrays.stream(Endpoint.values()).flatMap(endpoint -> Stream.of(Shape.DISTINCT, Shape.EMPTY_DISTINCT, Shape.REPEATED_EMPTY, Shape.ENDLESS_EMPTY)
                .map(shape -> DynamicTest.dynamicTest(endpoint+" / "+shape, () -> {
                    var probe = new Probe(shape, 65);
                    assertMalformed(rejected(server, endpoint, probe.request(endpoint, defaultQuery(endpoint), defaultBody(endpoint))));
                    assertEquals(64, probe.namesRead); assertEquals(64, probe.headerLookups);
                    assertEquals(shape == Shape.DISTINCT ? 64 : 1, probe.valuesRead);
                    assertFalse(probe.closed);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> underBoundDoesNotBecomeBlanketRejection() throws Exception {
        var server = server();
        return Stream.of(63, 64).map(count -> DynamicTest.dynamicTest("names="+count, () -> {
            var probe = new Probe(Shape.DISTINCT, count);
            var outcome = rejected(server, Endpoint.TOKEN, probe.request(Endpoint.TOKEN, null, FORM));
            assertEquals(OAuthServerException.Reason.UNSUPPORTED_GRANT_TYPE, outcome.reason());
            assertEquals(400, outcome.response().getStatusCode()); assertEquals(count, probe.namesRead); assertEquals(count, probe.valuesRead);
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> duplicatesAndCaseVariantsRemainVisibleToCore() throws Exception {
        var server = server();
        return Arrays.stream(Endpoint.values()).flatMap(endpoint -> Stream.of(Shape.DUPLICATE_TYPE, Shape.CASE_TYPE)
                .map(shape -> DynamicTest.dynamicTest(endpoint+" / "+shape, () -> {
                    var probe = new Probe(shape, shape == Shape.CASE_TYPE ? 2 : 1);
                    assertMalformed(rejected(server, endpoint, probe.request(endpoint, defaultQuery(endpoint), defaultBody(endpoint))));
                    assertEquals(2, probe.valuesRead);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> occurrenceOverflowRemainsBoundedAndRejecting() throws Exception {
        var server = server();
        return Arrays.stream(Endpoint.values()).map(endpoint -> DynamicTest.dynamicTest(endpoint.name(), () -> {
            var probe = new Probe(Shape.VALUE_OVERFLOW, 2);
            assertMalformed(rejected(server, endpoint, probe.request(endpoint, defaultQuery(endpoint), defaultBody(endpoint))));
            assertEquals(2, probe.namesRead); assertEquals(65, probe.valuesRead);
        }));
    }

    @Test void originalBodyAndQueryStillReachCoreWithoutParameterDecoding() throws Exception {
        var server = server();
        var ordinary = new Probe(Shape.DISTINCT, 1);
        assertEquals(OAuthServerException.Reason.UNSUPPORTED_GRANT_TYPE,
                rejected(server, Endpoint.TOKEN, ordinary.request(Endpoint.TOKEN, "tenant=a%2Bb", FORM)).reason());
        var invalidUtf8 = new Probe(Shape.DISTINCT, 1);
        assertMalformed(rejected(server, Endpoint.TOKEN, invalidUtf8.request(Endpoint.TOKEN, null, "grant_type=%FF")));
    }

    @Test void bodyReadKeepsTheExistingOneOverflowByteBound() throws Exception {
        var probe = new Probe(Shape.DISTINCT, 1);
        assertMalformed(rejected(server(), Endpoint.TOKEN, probe.request(Endpoint.TOKEN, null, "x".repeat(100_000))));
        assertEquals(65_537, probe.bodyRead); assertFalse(probe.closed);
    }

    @SuppressWarnings("NullAway") // Intentionally violates the required-argument contract.
    @Test void nullRequestRemainsProgrammerMisuse() throws Exception {
        var server = server();
        assertThrows(NullPointerException.class, () -> ServletOAuthAuthorizationServer.tokenResultFor(server, null));
    }

    private static @Nullable String defaultQuery(@NonNull Endpoint endpoint) { return endpoint == Endpoint.AUTHORIZATION ? AUTH_QUERY : null; }
    private static @NonNull String defaultBody(@NonNull Endpoint endpoint) { return endpoint == Endpoint.AUTHORIZATION ? "" : FORM; }
    private static @NonNull Rejection rejected(@NonNull OAuthAuthorizationServer server, @NonNull Endpoint endpoint, @NonNull HttpServletRequest request) {
        return switch (endpoint) {
            case AUTHORIZATION -> { var r = assertInstanceOf(OAuthAuthorizationResult.Rejected.class, assertDoesNotThrow(() -> ServletOAuthAuthorizationServer.beginAuthorizationResultFor(server, request, "A".repeat(43)))); yield new Rejection(r.getReason(), r.getResponse()); }
            case TOKEN -> { var r = assertInstanceOf(OAuthTokenResult.Rejected.class, assertDoesNotThrow(() -> ServletOAuthAuthorizationServer.tokenResultFor(server, request))); yield new Rejection(r.getReason(), r.getResponse()); }
            case REVOCATION -> { var r = assertInstanceOf(OAuthRevocationResult.Rejected.class, assertDoesNotThrow(() -> ServletOAuthAuthorizationServer.revocationResultFor(server, request))); yield new Rejection(r.getReason(), r.getResponse()); }
            case INTROSPECTION -> { var r = assertInstanceOf(OAuthIntrospectionResult.Rejected.class, assertDoesNotThrow(() -> ServletOAuthAuthorizationServer.introspectionResultFor(server, request))); yield new Rejection(r.getReason(), r.getResponse()); }
        };
    }
    private static void assertMalformed(@NonNull Rejection rejection) {
        assertEquals(OAuthServerException.Reason.MALFORMED_REQUEST, rejection.reason()); var response = rejection.response();
        assertEquals(400, response.getStatusCode()); assertEquals(List.of("no-store"), response.getHeaders().get("Cache-Control"));
        assertEquals(List.of("no-cache"), response.getHeaders().get("Pragma")); assertTrue(response.getLocationWithCredentials().isEmpty());
        byte[] expected = "{\"error\":\"invalid_request\"}".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(expected, response.toHttpBodyWithCredentials());
        for (String name : List.of("Set-Cookie", "Location", "Retry-After", "WWW-Authenticate")) assertFalse(response.getHeaders().containsKey(name));
        var output = new ByteArrayOutputStream(); Map<String,List<String>> fields = new LinkedHashMap<>(); int[] status = {0};
        ServletOutputStream stream = new ServletOutputStream() {
            @Override public void write(int value) { output.write(value); }
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(@NonNull WriteListener listener) { throw new AssertionError("Unexpected listener"); }
        };
        HttpServletResponse target = (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(), new Class<?>[]{HttpServletResponse.class}, (proxy, called, arguments) -> {
            switch (called.getName()) {
                case "setStatus" -> status[0] = (Integer) requireNonNull(arguments)[0];
                case "setHeader" -> fields.put((String) requireNonNull(arguments)[0], List.of((String) arguments[1]));
                case "addHeader" -> fields.computeIfAbsent((String) requireNonNull(arguments)[0], ignored -> new ArrayList<>()).add((String) arguments[1]);
                case "getOutputStream" -> { return stream; }
                default -> throw new AssertionError("Unexpected response operation " + called.getName());
            }
            return null;
        });
        assertDoesNotThrow(() -> ServletOAuthAuthorizationServer.writeResponse(target, response));
        assertEquals(400, status[0]); assertEquals(response.getHeaders(), fields); assertArrayEquals(expected, output.toByteArray());
    }

    private static final class Probe {
        private final @NonNull Shape shape; private final int count;
        private int namesRead, headerLookups, valuesRead, bodyRead; private boolean closed;
        private Probe(@NonNull Shape shape, int count) { this.shape = shape; this.count = count; }
        private @NonNull Enumeration<@NonNull String> names() {
            return new Enumeration<>() {
                private int cursor;
                @Override public boolean hasMoreElements() { return shape == Shape.ENDLESS_EMPTY || this.cursor < count; }
                @Override public @NonNull String nextElement() {
                    if (this.cursor >= 64) throw new AssertionError("Read past the header-name cutoff");
                    int index = this.cursor++; namesRead++;
                    return index == 0 ? "Content-Type" : shape == Shape.CASE_TYPE ? "content-type" :
                            shape == Shape.REPEATED_EMPTY || shape == Shape.ENDLESS_EMPTY || shape == Shape.VALUE_OVERFLOW ? "X" : "X-"+index;
                }
            };
        }
        private @NonNull Enumeration<@NonNull String> values(@NonNull String name) {
            this.headerLookups++;
            List<String> entries = name.equalsIgnoreCase("Content-Type") ? (this.shape == Shape.DUPLICATE_TYPE ? List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded") : List.of("application/x-www-form-urlencoded")) : this.shape == Shape.DISTINCT ? List.of("v") : List.of();
            return new Enumeration<>() {
                private int cursor;
                @Override public boolean hasMoreElements() { return shape == Shape.VALUE_OVERFLOW && name.equals("X") || this.cursor < entries.size(); }
                @Override public @NonNull String nextElement() {
                    if (++valuesRead > 65) throw new AssertionError("Read past the occurrence cutoff");
                    return shape == Shape.VALUE_OVERFLOW && name.equals("X") ? "v" : entries.get(this.cursor++);
                }
            };
        }
        private @NonNull HttpServletRequest request(@NonNull Endpoint endpoint, @Nullable String query, @NonNull String body) {
            var input = new ByteArrayInputStream(body.getBytes(StandardCharsets.US_ASCII));
            ServletInputStream stream = new ServletInputStream() {
                @Override public int read() { int value = input.read(); if (value >= 0) bodyRead++; return value; }
                @Override public int read(byte @NonNull [] bytes, int offset, int length) { int read = input.read(bytes, offset, length); if (read > 0) bodyRead += read; return read; }
                @Override public void close() { closed = true; }
                @Override public boolean isFinished() { return input.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(@NonNull ReadListener listener) { throw new AssertionError("Unexpected listener"); }
            };
            return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class}, (proxy, called, arguments) -> switch (called.getName()) {
                case "getMethod" -> endpoint == Endpoint.AUTHORIZATION ? "GET" : "POST";
                case "getQueryString" -> query;
                case "getInputStream" -> stream;
                case "getHeaderNames" -> names();
                case "getHeaders" -> values((String) requireNonNull(arguments)[0]);
                default -> throw new AssertionError("Unexpected request operation " + called.getName());
            });
        }
    }
}
