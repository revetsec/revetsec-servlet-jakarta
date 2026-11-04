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

import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.OAuthException;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Method rejection precedes query, body, header, parameter, cookie and session access. */
final class ServletOAuthCallbackMethodTests {
    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> unsupportedMethodsUseOnlyTheMethodAndReturnRejected() {
        return Stream.of("HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "get", "post", "CUSTOM", "GET ", "POST ")
                .map(method -> DynamicTest.dynamicTest(method, () -> {
                    List<String> calls = new ArrayList<>();
                    HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
                            new Class<?>[]{HttpServletRequest.class}, (proxy, called, arguments) -> {
                                calls.add(called.getName());
                                if ("getMethod".equals(called.getName())) return method;
                                throw new AssertionError("Unsupported method touched " + called.getName());
                            });
                    var rejected = assertInstanceOf(ServletOAuthCallbackResult.Rejected.class,
                            assertDoesNotThrow(() -> ServletOAuth.authorizationResponseResultFor(request)));
                    assertEquals(List.of("getMethod"), calls);
                    assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, rejected.getReason());
                    assertEquals("ServletOAuthCallbackResult{outcome=Rejected, data=<redacted>}", rejected.toString());
                }));
    }

    @Test void supportedGetRetainsRawQueryWithoutReadingBodyOrHeaders() throws IOException {
        var parsed = assertInstanceOf(ServletOAuthCallbackResult.Succeeded.class, ServletOAuth.authorizationResponseResultFor(
                request("GET", "code=a%2Bb%252Fc&state=x+y", null, List.of()))).getResponse();
        assertEquals("a+b%2Fc", parsed.getCode().orElseThrow());
        assertEquals("x y", parsed.getState().orElseThrow());
        assertEquals(AuthorizationRequestOptions.ResponseMode.QUERY, parsed.getResponseMode());
    }

    @Test void supportedPostRetainsOriginalBodyAndRawQuery() throws IOException {
        var parsed = assertInstanceOf(ServletOAuthCallbackResult.Succeeded.class, ServletOAuth.authorizationResponseResultFor(
                request("POST", "tenant=one", "code=a%2Bb&state=x+y", List.of("application/x-www-form-urlencoded")))).getResponse();
        assertEquals("a+b", parsed.getCode().orElseThrow());
        assertEquals("x y", parsed.getState().orElseThrow());
        assertEquals(List.of("one"), parsed.getParameters().get("tenant"));
        assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, parsed.getResponseMode());
    }

    @Test void duplicateContentTypeRemainsRejected() throws IOException {
        assertInstanceOf(ServletOAuthCallbackResult.Rejected.class, ServletOAuth.authorizationResponseResultFor(
                request("POST", null, "code=a&state=b", List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"))));
    }

    @Test void postOverflowRemainsTooLarge() throws IOException {
        assertInstanceOf(ServletOAuthCallbackResult.TooLarge.class, ServletOAuth.authorizationResponseResultFor(
                request("POST", null, "x".repeat(32_769), List.of("application/x-www-form-urlencoded"))));
    }

    @SuppressWarnings("NullAway") // Intentionally violates the required-argument contract.
    @Test void nullRequestRemainsProgrammerMisuse() {
        assertThrows(NullPointerException.class, () -> ServletOAuth.authorizationResponseResultFor(null));
    }

    private static @NonNull HttpServletRequest request(@NonNull String method, @Nullable String query,
            @Nullable String body, @NonNull List<@NonNull String> types) {
        return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, (proxy, called, arguments) -> switch (called.getName()) {
                    case "getMethod" -> method;
                    case "getQueryString" -> query;
                    case "getHeaders" -> {
                        if (!"POST".equals(method)) throw new AssertionError("GET read headers");
                        yield Collections.enumeration(types);
                    }
                    case "getInputStream" -> {
                        if (body == null) throw new AssertionError("Unexpected body read");
                        ByteArrayInputStream input = new ByteArrayInputStream(body.getBytes(StandardCharsets.US_ASCII));
                        yield new ServletInputStream() {
                            @Override public int read() { return input.read(); }
                            @Override public boolean isFinished() { return input.available() == 0; }
                            @Override public boolean isReady() { return true; }
                            @Override public void setReadListener(@NonNull ReadListener listener) { throw new UnsupportedOperationException(); }
                        };
                    }
                    default -> throw new AssertionError("Unexpected request access " + called.getName());
                });
    }
}
