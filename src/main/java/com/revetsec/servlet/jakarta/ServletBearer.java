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
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.BearerTokenResult;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static java.util.Objects.requireNonNull;

/** Raw Authorization-header transport. A parsed bearer credential remains unverified.
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletBearer {
    private ServletBearer() { }

    /** Parses every materialized Authorization occurrence without joining or trimming fields.
     * @param request application-routed resource request
     * @return absent, unverified present or malformed result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull BearerTokenResult bearerTokenResultFor(@NonNull HttpServletRequest request) {
        return BearerToken.fromAuthorizationHeaderValuesResult(authorizationValues(requireNonNull(request)));
    }

    private static @NonNull List<@NonNull String> authorizationValues(@NonNull HttpServletRequest request) {
        List<String> values = new ArrayList<>(2);
        Enumeration<String> original = request.getHeaders("Authorization");
        if (original == null) throw new IllegalStateException("Servlet request headers are unavailable");
        while (original.hasMoreElements() && values.size() < 2)
            values.add(requireNonNull(original.nextElement()));
        return List.copyOf(values);
    }
}
