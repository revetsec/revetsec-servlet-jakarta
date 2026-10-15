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
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthIssuerKeyProvider;
import com.revetsec.oauth.server.OAuthIssuerKeySnapshot;
import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import com.revetsec.oauth.server.OAuthServerClientAuthentication;
import com.revetsec.oauth.server.OAuthServerClientRegistration;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthStoreEntry;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreTransaction;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** A disposable, single-process issuer used only by the loopback transport qualification. */
final class M12Issuer {
    static final String ISSUER = "https://login.example.com/tenant";
    static final String RESOURCE = "https://resource.example/mcp";
    static final String REDIRECT = "https://client.example/cb?original=%2f";
    static final String CLIENT = "m12-client";
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    final OAuthAuthorizationServer server;

    M12Issuer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        OAuthIssuerKeySnapshot keys = OAuthIssuerKeySnapshot
                .withActiveKey(OAuthIssuerSigningKey.fromKeyPair("m12", pair.getPrivate(), pair.getPublic()))
                .generation("g1").publishedAt(Instant.now().minusSeconds(120)).build();
        OAuthServerClientRegistration client = OAuthServerClientRegistration.withClientId(CLIENT)
                .configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
                .allowedScopesByResource(Map.of(RESOURCE, Set.of("read")))
                .refreshTokenPermitted(true).build();
        OAuthServerClientRegistration resourceClient = OAuthServerClientRegistration.withClientId("resource")
                .configurationVersion("v1").authorizationCodePermitted(false)
                .introspectionResources(Set.of(RESOURCE))
                .authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) ->
                        MessageDigest.isEqual(secret, "secret".getBytes(StandardCharsets.UTF_8))))
                .build();
        byte[] material = new byte[32];
        for (int i = 0; i < material.length; i++) material[i] = (byte) (i + 1);
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("m12",
                Base64.getEncoder().encodeToString(material))).build();
        this.server = OAuthAuthorizationServer.withIssuer(ISSUER)
                .authorizationEndpoint(URI.create(ISSUER + "/authorize"))
                .tokenEndpoint(URI.create(ISSUER + "/token"))
                .jwksEndpoint(URI.create(ISSUER + "/jwks"))
                .revocationEndpoint(URI.create(ISSUER + "/revoke"))
                .introspectionEndpoint(URI.create(ISSUER + "/introspect"))
                .clientRepository((id, budget) -> id.equals(CLIENT) ? Optional.of(client)
                        : id.equals("resource") ? Optional.of(resourceClient) : Optional.empty())
                .store(new VolatileStore()).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys))
                .stateSealer(sealer).resources(Map.of(RESOURCE, Set.of("read")))
                .grantPolicy((context, budget) -> OAuthAuthorizationDecision.withSubject("subject")
                        .authorizedScopesByResource(Map.of(RESOURCE, Set.of("read")))
                        .refreshTokenPermitted(true).build())
                .refreshTokensEnabled(true).build();
        if (this.server.initializeFreshIssuer() != OAuthStoreCommitStatus.COMMITTED)
            throw new IllegalStateException("Issuer fixture initialization failed");
        this.server.establishNewSubject("subject");
    }

    private static final class VolatileStore implements OAuthAuthorizationServerStore {
        private final Map<OAuthStoreKey, OAuthStoreEntry> records = new HashMap<>();

        @Override public synchronized Optional<OAuthStoreEntry> read(OAuthStoreKey key, Duration remainingBudget) {
            if (remainingBudget.isZero() || remainingBudget.isNegative())
                throw new IllegalStateException("Issuer fixture budget exhausted");
            return Optional.ofNullable(this.records.get(key));
        }

        @Override public synchronized OAuthStoreCommitStatus commit(OAuthStoreTransaction transaction,
                Duration remainingBudget) {
            if (remainingBudget.isZero() || remainingBudget.isNegative())
                throw new IllegalStateException("Issuer fixture budget exhausted");
            for (OAuthStoreTransaction.Condition condition : transaction.getConditions()) {
                OAuthStoreEntry current = this.records.get(condition.getKey());
                Optional<String> actual = current == null ? Optional.empty() : Optional.of(current.getVersion());
                if (!condition.getExpectedVersion().equals(actual)) return OAuthStoreCommitStatus.CONFLICT;
            }
            for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations()) {
                if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE)
                    this.records.remove(mutation.getKey());
                else this.records.put(mutation.getKey(), mutation.getEntry().orElseThrow());
            }
            return OAuthStoreCommitStatus.COMMITTED;
        }
    }
}
