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
package example;

import example.provider.BackendApplication;
import com.revetsec.json.JsonObject;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Application-owned R9/R10 carrier for an injected common provider-token recipe.
 * Register an instance at a fixed {@code /providers/*} mapping. Configure the container's
 * header/body read deadlines and trusted HTTPS connector or authenticated proxy policy first.
 * This cookbook source adds no published Servlet adapter API.
 */
@ThreadSafe
@SuppressWarnings("serial") // Reconstruct injected services after restart; do not serialize this servlet.
public final class ServletProviderTokensRecipe extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final int MAXIMUM_BODY = 32_768;
    private final @NonNull BackendApplication application;

    /** Inject current account/admission policy and trusted provider configuration at application startup. */
    public ServletProviderTokensRecipe(@NonNull BackendApplication application) {
        this.application = Objects.requireNonNull(application);
    }

    /** Preserve original request multiplicity; never invoke Servlet parameter or cookie decoding. */
    @Override protected void service(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        BackendApplication.Reply reply;
        try {
            String path = request.getPathInfo();
            if (path == null || !request.getRequestURI().equals(
                    request.getContextPath() + request.getServletPath() + path)) {
                write(response, request, refusal(400)); return;
            }
            if (!request.isSecure() || !"https".equals(request.getScheme())) {
                write(response, request, refusal(400)); return;
            }
            Map<String, List<String>> headers = headers(request);
            if (request.getContentLengthLong() > MAXIMUM_BODY) {
                write(response, request, refusal(413)); return;
            }
            // The extra byte detects overflow even for an unknown/chunked Content-Length.
            // A complete bounded read is required; never feed a successful-looking prefix to the app.
            byte[] body = request.getInputStream().readNBytes(MAXIMUM_BODY + 1);
            if (body.length > MAXIMUM_BODY) {
                write(response, request, refusal(413)); return;
            }
            reply = this.application.handle(new BackendApplication.Request(
                    request.getMethod(), path, request.getQueryString(), headers, body,
                    false, true, request.getRemoteAddr()));
        } catch (IllegalArgumentException malformed) {
            reply = refusal(400);
        } catch (IOException unavailable) {
            reply = refusal(503);
        } catch (RuntimeException unavailable) {
            reply = refusal(503);
        }
        write(response, request, reply);
    }

    private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers(
            @NonNull HttpServletRequest request) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) throw new IllegalArgumentException("Request rejected");
        int nameCount = 0, occurrences = 0;
        long bytes = 0;
        while (names.hasMoreElements()) {
            if (++nameCount > 32) throw new IllegalArgumentException("Request rejected");
            String name = names.nextElement();
            if (name == null || name.length() > 64) throw new IllegalArgumentException("Request rejected");
            Enumeration<String> values = request.getHeaders(name);
            if (values == null) throw new IllegalArgumentException("Request rejected");
            List<String> copy = new ArrayList<>();
            while (values.hasMoreElements()) {
                if (++occurrences > 32) throw new IllegalArgumentException("Request rejected");
                String value = values.nextElement();
                if (value == null || value.length() > 4096) throw new IllegalArgumentException("Request rejected");
                bytes += name.length() + value.length();
                if (bytes > 8192) throw new IllegalArgumentException("Request rejected");
                copy.add(value);
            }
            if (copy.isEmpty() || result.putIfAbsent(name, List.copyOf(copy)) != null)
                throw new IllegalArgumentException("Request rejected");
        }
        return Map.copyOf(result);
    }

    private static BackendApplication.@NonNull Reply refusal(int status) {
        return new BackendApplication.Reply(status,
                Map.of("error", status >= 500 ? "Temporarily unavailable" : "Request denied"), List.of());
    }

    private static void write(@NonNull HttpServletResponse response,
            @NonNull HttpServletRequest request, BackendApplication.@NonNull Reply reply) throws IOException {
        response.setStatus(reply.status());
        reply.headers().forEach(response::setHeader);
        // Separate fields are required: completion emits both a new session and pending-cookie deletion.
        for (String cookie : reply.cookies()) response.addHeader("Set-Cookie", cookie);
        JsonObject.Builder body = JsonObject.builder();
        reply.fields().forEach(body::put);
        byte[] bytes = body.build().toJson().getBytes(StandardCharsets.UTF_8);
        response.setContentLength(bytes.length);
        if (!"HEAD".equals(request.getMethod())) response.getOutputStream().write(bytes);
    }
}
