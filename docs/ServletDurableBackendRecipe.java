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

import com.revetsec.StateSealer;
import com.revetsec.oauth.AuthorizationCompletionResult;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import example.pending.PostgresqlIssuerStore;
import example.pending.PostgresqlPendingAuthorizationStore;
import example.pending.PostgresqlWebAuthnStore;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;

/**
 * Compilable composition with the core repository's unpublished PostgreSQL reference stores.
 * The host owns the connection pool, schema, namespaces, browser session, keys, and restore barrier.
 */
public final class ServletDurableBackendRecipe {
    private ServletDurableBackendRecipe() { }

    /**
     * Open a fresh, clean connection to the authoritative primary within the remaining budget.
     * Pool acquisition, DNS, TLS and connection setup must obey that budget; do not share a transaction.
     */
    @FunctionalInterface
    public interface PrimaryConnectionSource {
        Connection open(Duration remaining) throws SQLException;
    }

    /** Provision the pending-store tables and namespace before using this store on any node. */
    public static PostgresqlPendingAuthorizationStore pendingStore(String namespace,
            PrimaryConnectionSource primary) {
        return new PostgresqlPendingAuthorizationStore(namespace, primary::open,
                1_024, 8 * 1_024, 4L * 1_024 * 1_024);
    }

    /** Only SAVED emits the redirect; the host handles collision, capacity and unavailable/indeterminate outcomes. */
    public static PendingAuthorizationSaveResult writeOAuthRedirect(AuthorizationRedirect redirect,
            PostgresqlPendingAuthorizationStore store, String browserBinding,
            HttpServletResponse response) {
        PendingAuthorizationSaveResult saved = redirect.getPendingAuthorization().saveToResult(store, browserBinding);
        if (saved == PendingAuthorizationSaveResult.SAVED)
            ServletWorkflowRecipes.writeOAuthRedirect(response, redirect);
        return saved;
    }

    /** Pass only a successful callback parse; consume once across nodes and clear pending browser state on every outcome. */
    public static AuthorizationCompletionResult completeOAuth(OAuthClient client,
            PostgresqlPendingAuthorizationStore store, String browserBinding,
            URI configuredCallback, AuthorizationResponse untrusted) {
        return ServletWorkflowRecipes.completeOAuth(client,
                PendingAuthorizationSource.fromStore(store, browserBinding), configuredCallback, untrusted);
    }

    /** The host also supplies registered clients, signing keys, persistent sealer, routes and policy. */
    public static OAuthAuthorizationServer.Builder withIssuerStore(
            OAuthAuthorizationServer.Builder configured, String namespace,
            PrimaryConnectionSource primary, int maximumEntries) {
        return configured.store(new PostgresqlIssuerStore(namespace, primary::open, maximumEntries));
    }

    /**
     * The host first sets its trusted RP ID and exact HTTPS origins on configured. The persistent
     * sealer and external recovery gate must be shared by every node using this namespace.
     */
    public static WebAuthnRelyingParty.Builder withWebAuthnStore(
            WebAuthnRelyingParty.Builder configured, String namespace,
            PrimaryConnectionSource primary, int maximumEntries,
            StateSealer persistentSealer, WebAuthnRecoveryGate externalRecoveryGate) {
        return configured.credentialNamespace(namespace)
                .store(new PostgresqlWebAuthnStore(namespace, primary::open, maximumEntries))
                .stateSealer(persistentSealer).recoveryGate(externalRecoveryGate);
    }
}
