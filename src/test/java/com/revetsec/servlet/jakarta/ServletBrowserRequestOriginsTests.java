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

import com.revetsec.BrowserRequestOriginPolicy;
import com.revetsec.BrowserRequestOriginResult;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class ServletBrowserRequestOriginsTests {
    private static final BrowserRequestOriginPolicy POLICY = BrowserRequestOriginPolicy
            .withAllowedOrigins(Set.of(URI.create("https://app.example.com"))).build();

    @Test
    void extractsMethodAndEveryHeaderOccurrence() {
        var allowed = ServletBrowserRequestOrigins.browserRequestOriginResultFor(POLICY,
                request("POST", Map.of("Sec-Fetch-Site", List.of("same-origin"), "Origin", List.of("null"))));
        assertEquals(BrowserRequestOriginResult.Basis.SAME_ORIGIN,
                assertInstanceOf(BrowserRequestOriginResult.Allowed.class, allowed).getBasis());

        var duplicate = ServletBrowserRequestOrigins.browserRequestOriginResultFor(POLICY,
                request("POST", Map.of("Origin", List.of("https://app.example.com", "https://app.example.com"))));
        assertEquals(BrowserRequestOriginResult.Reason.MALFORMED,
                assertInstanceOf(BrowserRequestOriginResult.Rejected.class, duplicate).getReason());
    }

    private static @NonNull HttpServletRequest request(@NonNull String method,
            @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers) {
        return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class}, (proxy, called, arguments) -> switch (called.getName()) {
                    case "getMethod" -> method;
                    case "getHeaders" -> Collections.enumeration(headers.getOrDefault((String) arguments[0], List.of()));
                    default -> throw new AssertionError(called.getName());
                });
    }
}
