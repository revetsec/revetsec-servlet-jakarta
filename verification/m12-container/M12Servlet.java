/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package example;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.servlet.jakarta.ServletOAuthCallbackResult;
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthIntrospectionResult;
import com.revetsec.oauth.server.OAuthIssuerAccessTokenResult;
import com.revetsec.oauth.server.OAuthRevocationResult;
import com.revetsec.oauth.server.OAuthTokenResult;
import com.revetsec.servlet.jakarta.ServletBearer;
import com.revetsec.servlet.jakarta.ServletOAuth;
import com.revetsec.servlet.jakarta.ServletOAuthAuthorizationServer;
import com.revetsec.servlet.jakarta.ServletWebAuthn;
import com.revetsec.servlet.jakarta.ServletWebAuthnBodyResult;
import com.revetsec.webauthn.InMemoryWebAuthnStore;
import com.revetsec.webauthn.WebAuthnAuthentication;
import com.revetsec.webauthn.WebAuthnAuthenticationRequestResult;
import com.revetsec.webauthn.WebAuthnAuthenticationResult;
import com.revetsec.webauthn.WebAuthnBrowserRequest;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRegistrationOptions;
import com.revetsec.webauthn.WebAuthnRegistrationRequestResult;
import com.revetsec.webauthn.WebAuthnRegistrationResult;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.revetsec.webauthn.WebAuthnSettings;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Private loopback application for actual Servlet transport qualification. */
public final class M12Servlet extends HttpServlet {
    private static final byte[] USER = M12Authenticator.HANDLE;
    private static final String APP_ORIGIN = M12Authenticator.ORIGIN;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final M12Issuer issuer;
    private final M12Authenticator authenticator;
    private final WebAuthnSettings settings = WebAuthnSettings.builder().maximumResponseBodyBytes(4096).build();
    private final WebAuthnRelyingParty relyingParty;

    public M12Servlet() {
        try {
            this.issuer = new M12Issuer();
            this.authenticator = new M12Authenticator();
            byte[] material = bindingBytes();
            StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("m12",
                    Base64.getEncoder().encodeToString(material))).build();
            WebAuthnRecoveryGate gate = remaining -> new WebAuthnRecoveryGate.Permit() {
                @Override public Boolean isCurrent() { return true; }
                @Override public void close() { }
            };
            this.relyingParty = WebAuthnRelyingParty.withRelyingPartyId(M12Authenticator.RP)
                    .relyingPartyName("M12 Qualification").allowedOrigins(Set.of(M12Authenticator.ORIGIN))
                    .credentialNamespace("m12").store(InMemoryWebAuthnStore.withLimits(128, 2_000_000))
                    .stateSealer(sealer).recoveryGate(gate).settings(this.settings).build();
        } catch (Exception failure) {
            throw new IllegalStateException("Private qualification fixture failed to initialize", failure);
        }
    }

    @Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        handle(request, response);
    }
    @Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        handle(request, response);
    }

    private void handle(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!privateCredential(request)) { send(response, 401, ""); return; }
        String path = request.getPathInfo();
        if (path == null) { send(response, 404, ""); return; }
        switch (path) {
            case "/health" -> send(response, 200, "ready");
            case "/session/start" -> startSession(request, response);
            case "/oauth/redirect" -> {
                if (!get(request, response)) return;
                ServletOAuth.writeRedirect(response, URI.create("https://provider.example/authorize?state=opaque%2Bstate"));
            }
            case "/oauth/callback" -> callback(request, response);
            case "/bearer" -> bearer(request, response);
            case "/as/metadata" -> ServletOAuthAuthorizationServer.writeResponse(response,
                    this.issuer.server.metadataResponse(request.getMethod()));
            case "/as/jwks" -> ServletOAuthAuthorizationServer.writeResponse(response,
                    this.issuer.server.jwksResponse(request.getMethod()));
            case "/as/authorize" -> authorize(request, response);
            case "/as/approve" -> approve(request, response);
            case "/as/token" -> token(request, response);
            case "/as/revoke" -> revoke(request, response);
            case "/as/introspect" -> introspect(request, response);
            case "/wa/register/start" -> registrationStart(request, response);
            case "/wa/register/complete" -> registrationComplete(request, response);
            case "/wa/authenticate/start" -> authenticationStart(request, response, false);
            case "/wa/reauthenticate/start" -> authenticationStart(request, response, true);
            case "/wa/authenticate/complete" -> authenticationComplete(request, response, false);
            case "/wa/reauthenticate/complete" -> authenticationComplete(request, response, true);
            case "/wa/test/registration-response" -> testResponse(request, response, true);
            case "/wa/test/assertion-response" -> testResponse(request, response, false);
            default -> send(response, 404, "");
        }
    }

    private static boolean privateCredential(HttpServletRequest request) {
        String expected = System.getProperty("fixture.credential", "");
        Enumeration<String> values = request.getHeaders("X-Fixture-Credential");
        if (expected.isEmpty() || values == null || !values.hasMoreElements()) return false;
        String supplied = values.nextElement();
        return !values.hasMoreElements() && expected.equals(supplied);
    }

    private record Session(String binding, String csrf) { }

    private void startSession(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!get(request, response)) return;
        String identity = randomText();
        String binding = randomText();
        String csrf = randomText();
        this.sessions.put(identity, new Session(binding, csrf));
        response.setHeader("Set-Cookie", "m12_session=" + identity
                + "; Path=/m12; Secure; HttpOnly; SameSite=Strict");
        response.setHeader("X-Fixture-Csrf", csrf);
        send(response, 200, "session");
    }

    private Session browserSession(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Enumeration<String> cookies = request.getHeaders("Cookie");
        Enumeration<String> origins = request.getHeaders("Origin");
        Enumeration<String> csrfValues = request.getHeaders("X-Fixture-Csrf");
        if (cookies == null || origins == null || csrfValues == null
                || !cookies.hasMoreElements() || !origins.hasMoreElements() || !csrfValues.hasMoreElements()) {
            send(response, 403, ""); return null;
        }
        String cookie = cookies.nextElement();
        String origin = origins.nextElement();
        String csrf = csrfValues.nextElement();
        if (cookies.hasMoreElements() || origins.hasMoreElements() || csrfValues.hasMoreElements()
                || !APP_ORIGIN.equals(origin) || !cookie.startsWith("m12_session=")
                || cookie.indexOf(';') >= 0) {
            send(response, 403, ""); return null;
        }
        Session session = this.sessions.get(cookie.substring("m12_session=".length()));
        if (session == null || !session.csrf().equals(csrf)) {
            send(response, 403, ""); return null;
        }
        return session;
    }

    private static String randomText() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return M12Authenticator.b64(bytes);
    }

    private static boolean get(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if ("GET".equals(request.getMethod())) return true;
        response.setHeader("Allow", "GET"); send(response, 405, ""); return false;
    }
    private static boolean post(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if ("POST".equals(request.getMethod())) return true;
        response.setHeader("Allow", "POST"); send(response, 405, ""); return false;
    }

    private static void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            ServletOAuthCallbackResult result = ServletOAuth.authorizationResponseResultFor(request);
            if (result instanceof ServletOAuthCallbackResult.Succeeded success) {
                AuthorizationResponse parsed = success.getResponse();
                send(response, 200, parsed.getResponseMode().name() + ":" + parsed.getState().orElse("absent"));
            } else send(response, 400, "");
        } catch (IllegalArgumentException rejected) {
            response.setHeader("Allow", "GET, POST"); send(response, 405, "");
        }
    }

    private void bearer(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!get(request, response)) return;
        BearerTokenResult result = ServletBearer.bearerTokenResultFor(request);
        if (result instanceof BearerTokenResult.Present present) {
            OAuthIssuerAccessTokenResult checked = this.issuer.server.validateAccessTokenResult(
                    present.getToken(), M12Issuer.RESOURCE);
            if (checked instanceof OAuthIssuerAccessTokenResult.Succeeded success
                    && success.getAccessToken().getScopes().contains("read")) send(response, 204, "");
            else {
                response.setHeader("WWW-Authenticate", "Bearer realm=\"m12\", error=\"invalid_token\"");
                send(response, 401, "");
            }
        } else if (result instanceof BearerTokenResult.Absent) {
            response.setHeader("WWW-Authenticate", "Bearer realm=\"m12\""); send(response, 401, "");
        } else send(response, 400, "");
    }

    private void authorize(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Session session = browserSession(request, response);
        if (session == null) return;
        OAuthAuthorizationResult result = ServletOAuthAuthorizationServer.beginAuthorizationResultFor(
                this.issuer.server, request, session.binding());
        if (result instanceof OAuthAuthorizationResult.InteractionRequired interaction)
            send(response, 200, interaction.getInteraction().getInteractionValue());
        else if (result instanceof OAuthAuthorizationResult.Completed completed)
            ServletOAuthAuthorizationServer.writeResponse(response, completed.getResponse());
        else if (result instanceof OAuthAuthorizationResult.Denied denied)
            ServletOAuthAuthorizationServer.writeResponse(response, denied.getResponse());
        else if (result instanceof OAuthAuthorizationResult.Rejected rejected)
            ServletOAuthAuthorizationServer.writeResponse(response, rejected.getResponse());
        else throw new IllegalStateException("Unknown authorization result");
    }

    private void approve(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!post(request, response)) return;
        Session session = browserSession(request, response);
        if (session == null) return;
        String interaction = queryValue(request, "interaction");
        if (interaction == null) { send(response, 400, ""); return; }
        OAuthAuthorizationDecision decision = OAuthAuthorizationDecision.withSubject("subject")
                .authorizedScopesByResource(Map.of(M12Issuer.RESOURCE, Set.of("read")))
                .refreshTokenPermitted(true).build();
        OAuthAuthorizationResult result = this.issuer.server.completeAuthorizationResult(
                interaction, session.binding(), decision);
        if (result instanceof OAuthAuthorizationResult.Completed completed)
            ServletOAuthAuthorizationServer.writeResponse(response, completed.getResponse());
        else if (result instanceof OAuthAuthorizationResult.Rejected rejected)
            ServletOAuthAuthorizationServer.writeResponse(response, rejected.getResponse());
        else if (result instanceof OAuthAuthorizationResult.Denied denied)
            ServletOAuthAuthorizationServer.writeResponse(response, denied.getResponse());
        else throw new IllegalStateException("Unexpected approval result");
    }

    private void token(HttpServletRequest request, HttpServletResponse response) throws IOException {
        OAuthTokenResult result = ServletOAuthAuthorizationServer.tokenResultFor(this.issuer.server, request);
        ServletOAuthAuthorizationServer.writeResponse(response,
                result instanceof OAuthTokenResult.Succeeded success ? success.getResponse()
                        : ((OAuthTokenResult.Rejected) result).getResponse());
    }
    private void revoke(HttpServletRequest request, HttpServletResponse response) throws IOException {
        OAuthRevocationResult result = ServletOAuthAuthorizationServer.revocationResultFor(this.issuer.server, request);
        ServletOAuthAuthorizationServer.writeResponse(response,
                result instanceof OAuthRevocationResult.Succeeded success ? success.getResponse()
                        : ((OAuthRevocationResult.Rejected) result).getResponse());
    }
    private void introspect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        OAuthIntrospectionResult result = ServletOAuthAuthorizationServer.introspectionResultFor(this.issuer.server, request);
        ServletOAuthAuthorizationServer.writeResponse(response,
                result instanceof OAuthIntrospectionResult.Succeeded success ? success.getResponse()
                        : ((OAuthIntrospectionResult.Rejected) result).getResponse());
    }

    private void registrationStart(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!post(request, response)) return;
        Session session = browserSession(request, response);
        if (session == null) return;
        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions.withUserHandle(USER)
                .userName("alice").userDisplayName("Alice Example").build();
        WebAuthnRegistrationRequestResult result = this.relyingParty.beginRegistrationResult(options, session.binding());
        if (result instanceof WebAuthnRegistrationRequestResult.Prepared prepared)
            ServletWebAuthn.writeBrowserRequest(response, prepared.getRequest());
        else send(response, 503, "");
    }
    private void authenticationStart(HttpServletRequest request, HttpServletResponse response,
            boolean reauthentication) throws IOException {
        if (!post(request, response)) return;
        Session session = browserSession(request, response);
        if (session == null) return;
        WebAuthnAuthenticationRequestResult result = reauthentication
                ? this.relyingParty.beginReauthenticationResult(USER, "transfer", session.binding())
                : this.relyingParty.beginAuthenticationResult(session.binding());
        if (result instanceof WebAuthnAuthenticationRequestResult.Prepared prepared)
            ServletWebAuthn.writeBrowserRequest(response, prepared.getRequest());
        else send(response, 503, "");
    }
    private void registrationComplete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!post(request, response)) return;
        Session session = browserSession(request, response);
        if (session == null) return;
        String ceremony = queryValue(request, "ceremony");
        if (ceremony == null) { send(response, 400, ""); return; }
        ServletWebAuthnBodyResult body = ServletWebAuthn.bodyResultFor(this.settings, request);
        if (!(body instanceof ServletWebAuthnBodyResult.Read read)) { bodyFailure(response, body); return; }
        WebAuthnRegistrationResult result = this.relyingParty.completeRegistrationResult(
                ceremony, read.getBodyWithPersonalData(), session.binding());
        if (result instanceof WebAuthnRegistrationResult.Succeeded) send(response, 204, "");
        else if (result instanceof WebAuthnRegistrationResult.Rejected) send(response, 400, "");
        else send(response, 503, "");
    }
    private void authenticationComplete(HttpServletRequest request, HttpServletResponse response,
            boolean reauthentication) throws IOException {
        if (!post(request, response)) return;
        Session session = browserSession(request, response);
        if (session == null) return;
        String ceremony = queryValue(request, "ceremony");
        if (ceremony == null) { send(response, 400, ""); return; }
        ServletWebAuthnBodyResult body = ServletWebAuthn.bodyResultFor(this.settings, request);
        if (!(body instanceof ServletWebAuthnBodyResult.Read read)) { bodyFailure(response, body); return; }
        WebAuthnAuthenticationResult result = reauthentication
                ? this.relyingParty.completeReauthenticationResult(USER, "transfer",
                        ceremony, read.getBodyWithPersonalData(), session.binding())
                : this.relyingParty.completeAuthenticationResult(
                        ceremony, read.getBodyWithPersonalData(), session.binding());
        if (result instanceof WebAuthnAuthenticationResult.Succeeded succeeded) {
            WebAuthnAuthentication proof = succeeded.getAuthentication();
            if (!MessageDigest.isEqual(USER, proof.getUserHandle())
                    || (!reauthentication && proof.getKind() != WebAuthnAuthentication.Kind.SIGN_IN)) {
                send(response, 500, ""); return;
            }
            send(response, 204, "");
        } else if (result instanceof WebAuthnAuthenticationResult.Rejected) send(response, 400, "");
        else send(response, 503, "");
    }

    private static void bodyFailure(HttpServletResponse response, ServletWebAuthnBodyResult result) throws IOException {
        send(response, result instanceof ServletWebAuthnBodyResult.Rejected ? 400 : 503, "");
    }
    private void testResponse(HttpServletRequest request, HttpServletResponse response,
            boolean registration) throws IOException {
        if (!get(request, response)) return;
        String challenge = queryValue(request, "challenge");
        if (challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")) {
            send(response, 400, ""); return;
        }
        try {
            byte[] payload = registration ? this.authenticator.registrationJson(challenge)
                    : this.authenticator.assertionJson(challenge,
                            "2".equals(queryValue(request, "counter")) ? 2 : 1);
            sendBytes(response, 200, payload);
        } catch (Exception failure) { throw new IllegalStateException("Synthetic authenticator failed", failure); }
    }

    private static String queryValue(HttpServletRequest request, String name) {
        String query = request.getQueryString();
        if (query == null) return null;
        String prefix = name + "=";
        String found = null;
        for (String field : query.split("&", -1)) if (field.startsWith(prefix)) {
            if (found != null) return null;
            found = field.substring(prefix.length());
        }
        return found;
    }
    private static byte[] bindingBytes() {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (65 + i);
        return bytes;
    }
    private static void send(HttpServletResponse response, int status, String body) throws IOException {
        sendBytes(response, status, body.getBytes(StandardCharsets.UTF_8));
    }
    private static void sendBytes(HttpServletResponse response, int status, byte[] body) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setContentType("application/json; charset=UTF-8");
        response.setContentLength(body.length);
        if (body.length > 0) response.getOutputStream().write(body);
    }
}
