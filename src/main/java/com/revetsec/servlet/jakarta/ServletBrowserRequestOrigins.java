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
import com.revetsec.BrowserRequestOriginPolicy;
import com.revetsec.BrowserRequestOriginResult;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Servlet request extraction for Revetsec's browser request-origin policy. The helper installs no filter and changes
 * no application state.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletBrowserRequestOrigins {
    private ServletBrowserRequestOrigins() { }

    /**
     * Checks the request method and all exposed {@code Sec-Fetch-Site} and {@code Origin} occurrences.
     *
     * @param policy configured core policy
     * @param request routed request
     * @return closed request-origin outcome
     * @throws NullPointerException if an argument is {@code null}
     * @throws IllegalStateException if Servlet request headers are unavailable
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull BrowserRequestOriginResult browserRequestOriginResultFor(
            @NonNull BrowserRequestOriginPolicy policy, @NonNull HttpServletRequest request) {
        requireNonNull(request);
        return requireNonNull(policy).checkResult(requireNonNull(request.getMethod()),
                valuesFor(request, "Sec-Fetch-Site"), valuesFor(request, "Origin"));
    }

    private static @NonNull List<@NonNull String> valuesFor(@NonNull HttpServletRequest request,
            @NonNull String name) {
        Enumeration<String> source = request.getHeaders(name);
        if (source == null) throw new IllegalStateException("Servlet request headers are unavailable");
        List<String> values = new ArrayList<>(2);
        while (source.hasMoreElements() && values.size() < 2)
            values.add(requireNonNull(source.nextElement()));
        return List.copyOf(values);
    }
}
