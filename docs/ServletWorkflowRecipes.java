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

import com.revetsec.oauth.AuthorizationCompletionResult;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.servlet.jakarta.ServletOAuthCallbackResult;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oauth.server.OAuthIntrospectionResult;
import com.revetsec.oauth.server.OAuthRevocationResult;
import com.revetsec.oauth.server.OAuthServerResponse;
import com.revetsec.oauth.server.OAuthTokenResult;
import com.revetsec.servlet.jakarta.ServletBearer;
import com.revetsec.servlet.jakarta.ServletOAuth;
import com.revetsec.servlet.jakarta.ServletOAuthAuthorizationServer;
import com.revetsec.servlet.jakarta.ServletWebAuthn;
import com.revetsec.servlet.jakarta.ServletWebAuthnBodyResult;
import com.revetsec.webauthn.WebAuthnAuthenticationRequestResult;
import com.revetsec.webauthn.WebAuthnAuthenticationResult;
import com.revetsec.webauthn.WebAuthnBrowserRequest;
import com.revetsec.webauthn.WebAuthnCredentialListResult;
import com.revetsec.webauthn.WebAuthnCredentialRemovalResult;
import com.revetsec.webauthn.WebAuthnRegistrationOptions;
import com.revetsec.webauthn.WebAuthnRegistrationRequestResult;
import com.revetsec.webauthn.WebAuthnRegistrationResult;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.revetsec.webauthn.WebAuthnSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

/** Compilable transport excerpts. The host performs the checks described in the companion guides. */
public final class ServletWorkflowRecipes {
    private ServletWorkflowRecipes() { }

    /** Persist or seal redirect.getPendingAuthorization() for this browser before calling this method. */
    public static void writeOAuthRedirect(HttpServletResponse response, AuthorizationRedirect redirect) {
        ServletOAuth.writeRedirect(response, redirect.getAuthorizationUri());
    }

    /** The host rejects malformed parsing before loading or consuming pending authorization state. */
    public static ServletOAuthCallbackResult oauthCallback(HttpServletRequest request) throws IOException {
        return ServletOAuth.authorizationResponseResultFor(request);
    }

    /** Pass only the callback from a successful parse; clear its pending browser cookie on every outcome. */
    public static AuthorizationCompletionResult completeOAuth(OAuthClient client,
            PendingAuthorizationSource pending, URI configuredCallback, AuthorizationResponse untrusted) {
        return client.completeAuthorizationResult(untrusted, pending, configuredCallback);
    }

    /** Parsing grants no identity or permission; validate and authorize a Present token in the host. */
    public static BearerTokenResult bearer(HttpServletRequest request) {
        return ServletBearer.bearerTokenResultFor(request);
    }

    /** Call only on this server's configured authorization route with an app-held browser binding. */
    public static OAuthAuthorizationResult beginIssuer(OAuthAuthorizationServer server,
            HttpServletRequest request, String browserBinding) throws IOException {
        return ServletOAuthAuthorizationServer.beginAuthorizationResultFor(server, request, browserBinding);
    }

    public static OAuthTokenResult token(OAuthAuthorizationServer server, HttpServletRequest request)
            throws IOException {
        return ServletOAuthAuthorizationServer.tokenResultFor(server, request);
    }

    public static OAuthRevocationResult revoke(OAuthAuthorizationServer server, HttpServletRequest request)
            throws IOException {
        return ServletOAuthAuthorizationServer.revocationResultFor(server, request);
    }

    public static OAuthIntrospectionResult introspect(OAuthAuthorizationServer server,
            HttpServletRequest request) throws IOException {
        return ServletOAuthAuthorizationServer.introspectionResultFor(server, request);
    }

    /** The host selects a core-prepared response, adds bounded app cookies, then emits it once. */
    public static void writeIssuer(HttpServletResponse response, OAuthServerResponse prepared)
            throws IOException {
        ServletOAuthAuthorizationServer.writeResponse(response, prepared);
    }

    public static void writeIssuerMetadata(OAuthAuthorizationServer server, HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        ServletOAuthAuthorizationServer.writeResponse(response, server.metadataResponse(request.getMethod()));
    }

    public static void writeIssuerKeys(OAuthAuthorizationServer server, HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        ServletOAuthAuthorizationServer.writeResponse(response, server.jwksResponse(request.getMethod()));
    }

    /** Enrollment starts only after the host has approved this account and its browser session. */
    public static WebAuthnRegistrationRequestResult beginRegistration(WebAuthnRelyingParty relyingParty,
            WebAuthnRegistrationOptions approvedAccount, String browserBinding) {
        return relyingParty.beginRegistrationResult(approvedAccount, browserBinding);
    }

    public static WebAuthnAuthenticationRequestResult beginSignIn(WebAuthnRelyingParty relyingParty,
            String browserBinding) {
        return relyingParty.beginAuthenticationResult(browserBinding);
    }

    public static WebAuthnAuthenticationRequestResult beginReauthentication(WebAuthnRelyingParty relyingParty,
            byte[] approvedUserHandle, String actionPurpose, String browserBinding) {
        return relyingParty.beginReauthenticationResult(approvedUserHandle, actionPurpose, browserBinding);
    }

    /** Only a Prepared request supplies browser JSON and its opaque ceremony handle. */
    public static void writeBrowserRequest(HttpServletResponse response, WebAuthnBrowserRequest prepared)
            throws IOException {
        ServletWebAuthn.writeBrowserRequest(response, prepared);
    }

    /** Branch on Read, Rejected and Unavailable before calling a core completion method. */
    public static ServletWebAuthnBodyResult readCeremony(WebAuthnSettings settings,
            HttpServletRequest request) {
        return ServletWebAuthn.bodyResultFor(settings, request);
    }

    /** Call only after the host accepts exact Host, Origin, CSRF, session and ceremony routing. */
    public static WebAuthnRegistrationResult completeRegistration(WebAuthnRelyingParty relyingParty,
            String ceremonyId, ServletWebAuthnBodyResult.Read body, String browserBinding) {
        return relyingParty.completeRegistrationResult(ceremonyId, body.getBodyWithPersonalData(), browserBinding);
    }

    /** A sign-in Succeeded contains proof; the host verifies the approved account and rotates its session. */
    public static WebAuthnAuthenticationResult completeAuthentication(WebAuthnRelyingParty relyingParty,
            String ceremonyId, ServletWebAuthnBodyResult.Read body, String browserBinding) {
        return relyingParty.completeAuthenticationResult(ceremonyId, body.getBodyWithPersonalData(), browserBinding);
    }

    /** Succeeded requires a reauthentication ceremony bound to this account and action purpose. */
    public static WebAuthnAuthenticationResult completeReauthentication(WebAuthnRelyingParty relyingParty,
            byte[] approvedUserHandle, String actionPurpose, String ceremonyId,
            ServletWebAuthnBodyResult.Read body, String browserBinding) {
        return relyingParty.completeReauthenticationResult(approvedUserHandle, actionPurpose,
                ceremonyId, body.getBodyWithPersonalData(), browserBinding);
    }

    public static WebAuthnCredentialListResult listCredentials(WebAuthnRelyingParty relyingParty,
            byte[] approvedUserHandle) {
        return relyingParty.listCredentialsResult(approvedUserHandle);
    }

    public static WebAuthnCredentialRemovalResult removeCredential(WebAuthnRelyingParty relyingParty,
            byte[] approvedUserHandle, byte[] credentialId) {
        return relyingParty.removeCredentialResult(approvedUserHandle, credentialId);
    }
}
