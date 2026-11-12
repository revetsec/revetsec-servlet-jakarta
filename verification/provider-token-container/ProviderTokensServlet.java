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

import example.provider.ProviderFixture;
import com.revetsec.json.JsonObject;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;

/** Private disposable host; its synthetic signing/control endpoints must never ship in an application. */
@ThreadSafe
@SuppressWarnings("serial")
public final class ProviderTokensServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final @NonNull ProviderFixture fixture;
    private final @NonNull ServletProviderTokensRecipe recipe;

    public ProviderTokensServlet() {
        try { this.fixture = new ProviderFixture(); }
        catch (IOException unavailable) { throw new IllegalStateException("Fixture unavailable"); }
        this.recipe = new ServletProviderTokensRecipe(this.fixture.application());
    }
    @Override protected void service(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        String expected = System.getenv().getOrDefault("REVETSEC_PROVIDER_FIXTURE_CREDENTIAL", "");
        String actual = one(request, "X-Fixture-Credential");
        if (expected.isEmpty() || actual == null || !MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII), actual.getBytes(StandardCharsets.US_ASCII))) {
            send(response, 401, JsonObject.builder().put("error", "Fixture denied").build()); return;
        }
        String path = request.getPathInfo();
        if (path != null && path.startsWith("/fixture/")) {
            if (!request.getMethod().equals("GET") || request.getQueryString() != null
                    || request.getContentLengthLong() > 0) {
                send(response, 400, JsonObject.builder().put("error", "Fixture denied").build()); return;
            }
            try {
                if (path.equals("/fixture/health")) {
                    send(response, 200, JsonObject.builder().put("healthy", true).build()); return;
                }
                if (path.startsWith("/fixture/token/")) {
                    String[] pieces = path.split("/", -1); String nonce = one(request, "X-Fixture-Nonce");
                    if (pieces.length != 5 || nonce == null) throw new IllegalArgumentException("Fixture denied");
                    send(response, 200, this.fixture.token(pieces[3], nonce, pieces[4])); return;
                }
                send(response, 200, this.fixture.control(path.substring("/fixture/".length()))); return;
            } catch (IllegalArgumentException malformed) {
                send(response, 400, JsonObject.builder().put("error", "Fixture denied").build()); return;
            }
        }
        this.recipe.service(request, response);
    }
    private static @Nullable String one(@NonNull HttpServletRequest request, @NonNull String name) {
        Enumeration<String> values = request.getHeaders(name);
        if (values == null || !values.hasMoreElements()) return null;
        String value = values.nextElement(); return values.hasMoreElements() ? null : value;
    }
    private static void send(@NonNull HttpServletResponse response, int status, @NonNull JsonObject body) throws IOException {
        response.setStatus(status); response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json; charset=UTF-8");
        byte[] bytes = body.toJson().getBytes(StandardCharsets.UTF_8); response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }
    @Override public void destroy() { this.fixture.close(); super.destroy(); }
}
