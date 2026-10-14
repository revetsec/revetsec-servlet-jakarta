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

import com.revetsec.servlet.jakarta.ServletSaml;
import com.revetsec.saml.PendingSamlLogoutSource;
import com.revetsec.saml.SamlAuthenticationResult;
import com.revetsec.saml.SamlLogoutPostResult;
import com.revetsec.saml.SamlLogoutRequestResult;
import com.revetsec.saml.SamlLogoutResponsePostResult;
import com.revetsec.saml.SamlLogoutResult;
import com.revetsec.saml.SamlLogoutStatus;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Private transport qualification endpoint; never deploy this test fixture as an application. */
public final class SamlServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private SamlFixture fixture;
    private SamlLogoutPostResult.Prepared prepared;
    private PendingSamlLogoutSource pending;
    private byte[] responseBody;
    private byte[] requestBody;
    private String credential;

    @Override public void init() throws ServletException {
        try {
            credential = System.getProperty("fixture.credential");
            reset();
        } catch (Exception failure) { throw new ServletException("Fixture startup failed", failure); }
    }

    private void reset() throws Exception {
        fixture = new SamlFixture();
        SamlLogoutPostResult result = fixture.sp.beginPostLogoutResult(fixture.idp, fixture.session);
        if (!(result instanceof SamlLogoutPostResult.Prepared value))
            throw new IllegalStateException("Fixture logout preparation rejected");
        prepared = value;
        pending = fixture.pendingSource(value.getPendingLogout());
        responseBody = fixture.responseBody(value.getPendingLogout());
        requestBody = fixture.requestBody("_idp-logout");
    }

    @Override protected synchronized void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (!Arrays.equals(("Bearer " + credential).getBytes(StandardCharsets.US_ASCII),
                String.valueOf(request.getHeader("Authorization")).getBytes(StandardCharsets.US_ASCII))) {
            response.setStatus(401); return;
        }
        String path = request.getPathInfo();
        if ("GET".equals(request.getMethod())) {
            switch (path) {
                case "/begin" -> {
                    response.setHeader("Set-Cookie", "fixture-pending=opaque; Secure; HttpOnly; SameSite=None");
                    response.setHeader("Content-Security-Policy", "default-src 'none'; form-action https://idp.example.test");
                    ServletSaml.writeLogoutPostForm(response, prepared, null);
                }
                case "/fixture/request" -> writeFixture(response, requestBody);
                case "/fixture/response" -> writeFixture(response, responseBody);
                case "/fixture/form" -> writeFixture(response, prepared.getPostForm().toHtml(null).getBytes(StandardCharsets.UTF_8));
                case "/reset" -> {
                    try { reset(); } catch (Exception failure) { throw new ServletException("Fixture reset failed", failure); }
                    response.setStatus(204);
                }
                default -> response.setStatus(405);
            }
            return;
        }
        if (!"POST".equals(request.getMethod()) || (!"/logout".equals(path) && !"/acs".equals(path))) {
            response.setStatus(405); return;
        }
        SamlPostBindingParseResult parsed = "/acs".equals(path)
                ? ServletSaml.postBindingResultFor(request) : ServletSaml.postLogoutBindingResultFor(request);
        if (!(parsed instanceof SamlPostBindingParseResult.Parsed value)) {
            response.setStatus(400); return;
        }
        SamlPostBindingMessage message = value.getMessage();
        if ("/acs".equals(path)) {
            response.setStatus(fixture.sp.completeUnsolicitedAuthenticationResult(message, fixture.idp)
                    instanceof SamlAuthenticationResult.Succeeded ? 204 : 400);
            return;
        }
        if (message.getKind() == SamlPostBindingMessage.Kind.RESPONSE) {
            response.setStatus(fixture.sp.completeLogoutResult(message, pending, fixture.idp)
                    instanceof SamlLogoutResult.Succeeded ? 204 : 400);
            return;
        }
        SamlLogoutRequestResult accepted = fixture.sp.acceptLogoutRequestResult(message, fixture.idp);
        if (!(accepted instanceof SamlLogoutRequestResult.Accepted checked)) {
            response.setStatus(400); return;
        }
        SamlLogoutResponsePostResult reply = fixture.sp.respondToPostLogoutRequestResult(
                checked.getRequest(), fixture.idp, SamlLogoutStatus.SUCCESS);
        if (!(reply instanceof SamlLogoutResponsePostResult.Prepared outgoing)) {
            response.setStatus(503); return;
        }
        ServletSaml.writeLogoutResponsePostForm(response, outgoing, null);
    }

    private static void writeFixture(HttpServletResponse response, byte[] body) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Content-Type", "application/octet-stream");
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
