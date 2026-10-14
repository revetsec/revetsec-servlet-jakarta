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

import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import com.revetsec.scim.*;
import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.MarshaledResponseBody;
import com.soklet.servlet.jakarta.SokletHttpServletRequest;
import com.soklet.servlet.jakarta.SokletHttpServletResponse;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponseWrapper;
import jakarta.servlet.ServletOutputStream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Paired raw-input and failure-boundary contracts; real container probes live in verification/scim-container. */
final class ServletScimTests {
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull String SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";

    @Test void rawQueryKeepsMultiplicityAndPercentEncoding() {
        ScimServiceProvider provider = provider();
        assertEquals(0, assertInstanceOf(ScimQueryParseResult.Succeeded.class,
                ServletScim.queryResultFor(provider, USER, request("?count=-1&startIndex=0"))).getQuery().getCount());
        for (String query : List.of("?count=1&count=2", "?count=%252D1"))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, ServletScim.queryResultFor(provider, USER, request(query)));
        assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                ServletScim.attributeSelectionResultFor(provider, USER, request("?attributes=userName%2CdisplayName")));
        assertInstanceOf(ScimAttributeSelectionResult.Rejected.class,
                ServletScim.attributeSelectionResultFor(provider, USER, request("?attributes=userName&excludedAttributes=displayName")));
    }

    @Test void bodyCapReadsOnlyOneOverflowByteAndNeverReturnsAnOverflowPayload() {
        ScimServiceProvider provider = provider(ScimLimits.builder().maximumBodyBytes(16_384).build());
        for (int length : List.of(0, 16_383, 16_384, 16_385, 100_000)) {
            CountingStream stream = new CountingStream(length, null);
            ServletScimBodyResult result = ServletScim.bodyResultFor(provider, withStream(stream));
            assertEquals(Math.min(length, 16_385), stream.read);
            assertFalse(stream.closed);
            if (length > 16_384) assertSame(ScimError.requestTooLargeInstance(),
                    assertInstanceOf(ServletScimBodyResult.Rejected.class, result).getError());
            else assertEquals(length, assertInstanceOf(ServletScimBodyResult.Read.class, result).getBodyWithPersonalData().length);
            assertFalse(result.toString().contains("private"));
        }
    }

    @Test void bodyReadsAreDefensiveAndCoreParsersReceiveExactUtf8Bytes() {
        byte[] original = ("{\"schemas\":[\"" + SCHEMA + "\"],\"userName\":\"private+a%20é\"}").getBytes(StandardCharsets.UTF_8);
        Request raw = Request.withRawUrl(HttpMethod.POST, "/scim/Users")
                .headers(Map.of("Content-Type", List.of("application/scim+json"))).body(original).build();
        HttpServletRequest request = SokletHttpServletRequest.fromRequest(raw);
        ServletScimBodyResult.Read read = assertInstanceOf(ServletScimBodyResult.Read.class,
                ServletScim.bodyResultFor(provider(), request));
        byte[] exposed = read.getBodyWithPersonalData();
        assertArrayEquals(original, exposed); Arrays.fill(exposed, (byte) 0);
        assertArrayEquals(original, read.getBodyWithPersonalData());
        ScimResource candidate = assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                provider().parseResourceResult(USER, ServletScim.contentTypeHeaderValuesFor(request), read.getBodyWithPersonalData())).getResource();
        assertEquals("private+a%20é", ScimUser.fromResource(candidate).getUserName());
        ServletScimBodyResult.Read direct = new ServletScimBodyResult.Read(original);
        Arrays.fill(original, (byte) 0);
        assertEquals('{', direct.getBodyWithPersonalData()[0]);
        assertEquals("ServletScimBodyResult.Read{<redacted>}", direct.toString());
    }

    @Test void ioFailureReleasesNoPartialBodyAndInterruptedFailureKeepsTheFlag() {
        ServletScimBodyResult first = ServletScim.bodyResultFor(provider(), withStream(new CountingStream(7, new IOException("private"))));
        assertInstanceOf(ServletScimBodyResult.Unavailable.class, first);
        assertEquals("ServletScimBodyResult.Unavailable", first.toString());
        try {
            ServletScimBodyResult interrupted = ServletScim.bodyResultFor(provider(),
                    withStream(new CountingStream(7, new InterruptedIOException("private"))));
            assertSame(first, interrupted);
            assertTrue(Thread.currentThread().isInterrupted());
            AtomicInteger acquisitions = new AtomicInteger();
            HttpServletRequest untouched = new HttpServletRequestWrapper(request("")) {
                @Override public @NonNull ServletInputStream getInputStream() {
                    acquisitions.incrementAndGet(); return new CountingStream(1, null);
                }
            };
            assertSame(first, ServletScim.bodyResultFor(provider(), untouched));
            assertEquals(0, acquisitions.get());
        } finally { Thread.interrupted(); }
        assertSame(first, ServletScim.bodyResultFor(provider(), withStream(new CountingStream(0, new SocketTimeoutException()))));
        assertFalse(Thread.currentThread().isInterrupted());
    }

    @Test void cancellationDuringAReadNeverReleasesAPartialOrCompleteBody() {
        ServletInputStream cancelled = new ServletInputStream() {
            @Override public int read() { Thread.currentThread().interrupt(); return -1; }
            @Override public boolean isFinished() { return false; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(@Nullable ReadListener listener) { }
        };
        try {
            assertInstanceOf(ServletScimBodyResult.Unavailable.class, ServletScim.bodyResultFor(provider(), withStream(cancelled)));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
    }

    @Test void contentTypeEnumerationIsLazyBoundedAndKeepsDuplicatePhysicalOccurrences() {
        AtomicInteger reads = new AtomicInteger();
        HttpServletRequest hostile = headers("Content-Type", new Enumeration<>() {
            @Override public boolean hasMoreElements() { return true; }
            @Override public @NonNull String nextElement() { reads.incrementAndGet(); return "application/scim+json"; }
        });
        List<String> values = ServletScim.contentTypeHeaderValuesFor(hostile);
        assertEquals(0, reads.get());
        ScimResourceParseResult.Rejected rejected = assertInstanceOf(ScimResourceParseResult.Rejected.class,
                provider().parseResourceResult(USER, values, new byte[0]));
        assertSame(ScimError.unsupportedMediaTypeInstance(), rejected.getError());
        assertEquals(2, reads.get()); assertEquals(2, values.size()); assertEquals(2, reads.get());
        assertThrows(UnsupportedOperationException.class, () -> values.add("application/json"));
        HttpServletRequest absent = new HttpServletRequestWrapper(request("")) {
            @Override public @Nullable Enumeration<@NonNull String> getHeaders(@NonNull String name) { return null; }
        };
        assertTrue(ServletScim.contentTypeHeaderValuesFor(absent).isEmpty());
    }

    @Test void conditionalsKeepAllOccurrencesAndDoNotJoinWildcardWithATag() {
        ScimResource current = resource(); ScimServiceProvider provider = provider();
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ServletScim.ifMatchResultFor(provider, current,
                headers("If-Match", Collections.enumeration(List.of("\"old\"", "\"v\"")))));
        assertSame(ScimError.invalidSyntaxInstance(), assertInstanceOf(ScimIfMatchResult.Rejected.class,
                ServletScim.ifMatchResultFor(provider, current,
                        headers("If-Match", Collections.enumeration(List.of("*", "\"v\""))))).getError());
        assertInstanceOf(ScimIfNoneMatchResult.NotModified.class, ServletScim.ifNoneMatchResultFor(provider, current,
                headers("If-None-Match", Collections.enumeration(List.of("\"v\"")))));
        AtomicInteger reads = new AtomicInteger();
        HttpServletRequest hostile = headers("If-Match", new Enumeration<>() {
            @Override public boolean hasMoreElements() { return true; }
            @Override public @NonNull String nextElement() { reads.incrementAndGet(); return "\"v\""; }
        });
        assertSame(ScimError.requestTooLargeInstance(), assertInstanceOf(ScimIfMatchResult.Rejected.class,
                ServletScim.ifMatchResultFor(provider, current, hostile)).getError());
        assertEquals(provider.getLimits().getMaximumConditionalTags() + 1, reads.get());
    }

    @Test void responsesKeepPreparedBytesHeadersAndBodylessResponsesNeverAcquireAStream() throws IOException {
        ScimServiceProvider provider = provider();
        ScimResponse notModified = assertInstanceOf(ScimResponseResult.Prepared.class,
                provider.notModifiedResponseResult(resource())).getResponse();
        for (ScimResponse prepared : List.of(provider.errorResponse(ScimError.invalidValueInstance()),
                provider.noContentResponse(), notModified)) {
            SokletHttpServletResponse response = SokletHttpServletResponse.fromHttpServletRequest(request(""));
            AtomicInteger streamCalls = new AtomicInteger();
            ServletScim.writeResponse(new HttpServletResponseWrapper(response) {
                @Override public @NonNull ServletOutputStream getOutputStream() throws IOException {
                    streamCalls.incrementAndGet(); return response.getOutputStream();
                }
            }, prepared);
            assertEquals(prepared.getStatusCode(), response.getStatus());
            prepared.getHeaders().forEach((name, values) -> assertEquals(values, List.copyOf(response.getHeaders(name))));
            assertArrayEquals(prepared.toHttpBodyWithPersonalData(), response.toMarshaledResponse().getBody().map(body -> assertInstanceOf(MarshaledResponseBody.Bytes.class, body).getBytes()).orElseGet(() -> new byte[0]));
            assertEquals(prepared.toHttpBodyWithPersonalData().length == 0 ? 0 : 1, streamCalls.get());
        }
    }

    @Test void transportWriteFailureStaysAnIOException() {
        SokletHttpServletResponse response = SokletHttpServletResponse.fromHttpServletRequest(request(""));
        assertThrows(IOException.class, () -> ServletScim.writeResponse(new HttpServletResponseWrapper(response) {
            @Override public @NonNull ServletOutputStream getOutputStream() throws IOException { throw new IOException("private"); }
        }, provider().errorResponse(ScimError.invalidValueInstance())));
    }

    private static @NonNull HttpServletRequest request(@NonNull String query) {
        return SokletHttpServletRequest.fromRequest(Request.fromRawUrl(HttpMethod.GET, "/scim/Users" + query));
    }
    private static @NonNull HttpServletRequest headers(@NonNull String expected,
            @NonNull Enumeration<@NonNull String> values) {
        return new HttpServletRequestWrapper(request("")) {
            @Override public @Nullable Enumeration<@NonNull String> getHeaders(@NonNull String name) {
                assertEquals(expected, name); return values;
            }
            @Override public @Nullable String getParameter(@NonNull String name) { throw new AssertionError("parameter decoding"); }
        };
    }
    private static @NonNull HttpServletRequest withStream(@NonNull ServletInputStream stream) {
        return new HttpServletRequestWrapper(request("")) {
            @Override public @NonNull ServletInputStream getInputStream() { return stream; }
        };
    }
    private static @NonNull ScimServiceProvider provider() { return provider(ScimLimits.fromDefaults()); }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimLimits limits) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER)).limits(limits).build();
    }
    private static @NonNull ScimResource resource() {
        return ScimResource.withResourceType(USER).document(JsonObject.builder()
                .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(SCHEMA))))
                .put("id", "u").put("userName", "old")
                .put("meta", JsonObject.builder().put("version", "\"v\"").build()).build()).build();
    }
    private static final class CountingStream extends ServletInputStream {
        private final int length;
        private final @Nullable IOException failure;
        private int read;
        private boolean closed;
        private CountingStream(int length, @Nullable IOException failure) { this.length = length; this.failure = failure; }
        @Override public int read() throws IOException {
            if (read == length) { if (failure != null) throw failure; return -1; }
            ++read; return 'a';
        }
        @Override public boolean isFinished() { return read == length; }
        @Override public boolean isReady() { return true; }
        @Override public void setReadListener(@Nullable ReadListener listener) { }
        @Override public void close() { closed = true; }
    }
}
