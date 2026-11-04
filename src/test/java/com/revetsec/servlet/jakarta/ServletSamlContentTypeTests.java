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

import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;

/** Cardinality rejection is bounded and never reads a request body or hostile enumeration tail. */
final class ServletSamlContentTypeTests {
    private static final String TYPE = "application/x-www-form-urlencoded";
    private static final String FORM = "SAMLResponse=PGEvPg%3D%3D&RelayState=alpha%2Bbeta%252F";
    private enum Tail { FINITE_MILLION, ENDLESS, NO_FURTHER_PROBES }
    private record Profile(boolean logout, @NonNull String field, SamlPostBindingMessage.@NonNull Kind kind) { }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> duplicateHeadersStopBeforeAnyThirdValueOrProbe() {
        return Stream.of(false, true).flatMap(logout -> Arrays.stream(Tail.values()).map(tail ->
                DynamicTest.dynamicTest("logout="+logout+" / "+tail, () -> {
                    int[] next = {0}, probes = {0};
                    Enumeration<String> values = new Enumeration<>() {
                        @Override public boolean hasMoreElements() {
                            probes[0]++;
                            if (tail == Tail.NO_FURTHER_PROBES && next[0] >= 2)
                                throw new AssertionError("Probed enumeration after duplicate refusal was certain");
                            return tail != Tail.FINITE_MILLION || next[0] < 1_000_000;
                        }
                        @Override public @NonNull String nextElement() {
                            if (next[0] >= 2) throw new AssertionError("Read a third Content-Type value");
                            next[0]++; return TYPE;
                        }
                    };
                    var request = new Probe(values); request.forbidBody = true; request.query = "SAMLResponse=untrusted";
                    assertRejected(assertDoesNotThrow(() -> parse(logout, request.request("POST"))), SamlPostBindingParseResult.Reason.CONTENT_TYPE);
                    assertEquals(2, next[0]); assertEquals(2, probes[0]); assertEquals(0, request.bodyReads); assertFalse(request.closed);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> exactlyTwoRealOccurrencesRemainARejection() {
        return Stream.of(false, true).flatMap(logout -> Stream.of(List.of(TYPE, TYPE), List.of(TYPE, "text/plain"))
                .map(values -> DynamicTest.dynamicTest("logout="+logout+" / "+values, () -> {
                    var request = new Probe(Collections.enumeration(values)); request.forbidBody = true;
                    assertRejected(parse(logout, request.request("POST")), SamlPostBindingParseResult.Reason.CONTENT_TYPE);
                    assertEquals(0, request.bodyReads);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> missingEnumerationAndEmptyEnumerationRejectWithoutBody() {
        return Stream.of(false, true).flatMap(logout -> Stream.of(false, true).map(unavailable ->
                DynamicTest.dynamicTest("logout="+logout+" / null-enumeration="+unavailable, () -> {
                    var request = new Probe(unavailable ? null : Collections.emptyEnumeration()); request.forbidBody = true;
                    assertRejected(parse(logout, request.request("POST")), SamlPostBindingParseResult.Reason.CONTENT_TYPE);
                    assertEquals(0, request.bodyReads);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedSingletonMediaRejectsWithoutBody() {
        return Stream.of(false, true).flatMap(logout -> Stream.of("text/plain", "application/x-www-form-urlencoded; charset=iso-8859-1")
                .map(value -> DynamicTest.dynamicTest("logout="+logout+" / "+value, () -> {
                    var request = new Probe(Collections.enumeration(List.of(value))); request.forbidBody = true;
                    assertRejected(parse(logout, request.request("POST")), SamlPostBindingParseResult.Reason.CONTENT_TYPE);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> validSingleHeaderRetainsRawBodyQueryKindAndOpaqueRelayState() {
        return Stream.of(new Profile(false, "SAMLResponse", SamlPostBindingMessage.Kind.RESPONSE),
                new Profile(true, "SAMLRequest", SamlPostBindingMessage.Kind.REQUEST),
                new Profile(true, "SAMLResponse", SamlPostBindingMessage.Kind.RESPONSE))
                .map(profile -> DynamicTest.dynamicTest(profile.toString(), () -> {
                    var request = ordinary(); request.query = "tenant=a%2Bb";
                    request.body = FORM.replace("SAMLResponse", profile.field()).getBytes(StandardCharsets.US_ASCII);
                    var message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                            parse(profile.logout(), request.request("POST"))).getMessage();
                    assertEquals(profile.kind(), message.getKind()); assertEquals("alpha+beta%2F", message.getRelayState().orElseThrow());
                    assertEquals(request.body.length, request.bodyReads); assertFalse(request.closed);
                }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> queryAndBase64RefusalsRemainCoreDecisions() {
        return Stream.of(false, true).flatMap(logout -> Stream.of(false, true).map(query ->
                DynamicTest.dynamicTest("logout="+logout+" / bad-query="+query, () -> {
                    var request = ordinary();
                    if (query) request.query = "SAMLResponse=untrusted";
                    else request.body = "SAMLResponse=@@@".getBytes(StandardCharsets.US_ASCII);
                    assertRejected(parse(logout, request.request("POST")), query ? SamlPostBindingParseResult.Reason.QUERY : SamlPostBindingParseResult.Reason.BASE64);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> bodyReadsKeepTheOneOverflowByteBound() {
        return Stream.of(false, true).map(logout -> DynamicTest.dynamicTest("logout="+logout, () -> {
            var request = ordinary(); request.body = new byte[1_200_000];
            assertRejected(parse(logout, request.request("POST")), SamlPostBindingParseResult.Reason.BODY_SIZE);
            assertEquals(1_061_129, request.bodyReads); assertFalse(request.closed);
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> genuineBodyIoFailurePropagates() {
        return Stream.of(false, true).map(logout -> DynamicTest.dynamicTest("logout="+logout, () -> {
            var request = ordinary(); var failure = new IOException("Synthetic body failure"); request.failure = failure;
            assertSame(failure, assertThrows(IOException.class, () -> parse(logout, request.request("POST"))));
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedMethodKeepsTheExistingRouteContract() {
        return Stream.of(false, true).map(logout -> DynamicTest.dynamicTest("logout="+logout, () -> {
            var request = ordinary(); request.forbidBody = true;
            assertThrows(IllegalArgumentException.class, () -> parse(logout, request.request("GET")));
            assertEquals(0, request.headerCalls); assertEquals(0, request.bodyReads);
        }));
    }

    @SuppressWarnings("NullAway") // Intentionally violates required-argument contracts.
    @TestFactory @NonNull Stream<@NonNull DynamicTest> nullRequestRemainsProgrammerMisuse() {
        return Stream.of(false, true).map(logout -> DynamicTest.dynamicTest("logout="+logout, () ->
                assertThrows(NullPointerException.class, () -> parse(logout, null))));
    }

    private static @NonNull SamlPostBindingParseResult parse(boolean logout, @NonNull HttpServletRequest request) throws IOException {
        return logout ? ServletSaml.postLogoutBindingResultFor(request) : ServletSaml.postBindingResultFor(request);
    }
    private static void assertRejected(@NonNull SamlPostBindingParseResult result, SamlPostBindingParseResult.@NonNull Reason reason) {
        assertEquals(reason, assertInstanceOf(SamlPostBindingParseResult.Rejected.class, result).getReason());
    }
    private static @NonNull Probe ordinary() { return new Probe(Collections.enumeration(List.of(TYPE))); }
    private static final class Probe {
        private final @Nullable Enumeration<@NonNull String> types;
        private byte @NonNull [] body = FORM.getBytes(StandardCharsets.US_ASCII);
        private @Nullable String query;
        private @Nullable IOException failure;
        private boolean forbidBody, closed;
        private int bodyReads, headerCalls;
        private Probe(@Nullable Enumeration<@NonNull String> types) { this.types = types; }
        private @NonNull HttpServletRequest request(@NonNull String method) {
            return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                    (proxy, called, arguments) -> switch (called.getName()) {
                        case "getMethod" -> method;
                        case "getHeaders" -> { assertEquals("Content-Type", requireNonNull(arguments)[0]); headerCalls++; yield types; }
                        case "getQueryString" -> query;
                        case "getInputStream" -> {
                            if (forbidBody) throw new AssertionError("Invalid Content-Type must not access the body");
                            if (failure != null) throw failure;
                            var input = new ByteArrayInputStream(body);
                            yield new ServletInputStream() {
                                @Override public int read() { int value = input.read(); if (value >= 0) bodyReads++; return value; }
                                @Override public int read(byte @NonNull [] bytes, int offset, int length) { int read = input.read(bytes, offset, length); if (read > 0) bodyReads += read; return read; }
                                @Override public void close() { closed = true; }
                                @Override public boolean isFinished() { return input.available() == 0; }
                                @Override public boolean isReady() { return true; }
                                @Override public void setReadListener(@NonNull ReadListener listener) { throw new AssertionError("Unexpected listener"); }
                            };
                        }
                        default -> throw new AssertionError("Unexpected request operation " + called.getName());
                    });
        }
    }
}
