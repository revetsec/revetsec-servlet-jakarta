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
package example.provider;

import com.revetsec.jose.RemoteJwksSource;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Synthetic test-only provider keys/clock/account backend; never install this fixture as an app. */
@ThreadSafe
public final class ProviderFixture implements AutoCloseable {
    private static final @NonNull KeyPair GOOGLE = key("TEST-ONLY-google-container"),
            APPLE = key("TEST-ONLY-apple-container"), OTHER = key("TEST-ONLY-hostile-container");
    private final @NonNull MutableClock clock = new MutableClock();
    private final @NonNull ExecutorService executor = Executors.newFixedThreadPool(2);
    private final @NonNull HttpServer server;
    private final @NonNull AtomicInteger googleFetches = new AtomicInteger(), appleFetches = new AtomicInteger(),
            attackerFetches = new AtomicInteger(), lookups = new AtomicInteger(), authorizations = new AtomicInteger();
    private final @NonNull AtomicBoolean policy = new AtomicBoolean(true), admission = new AtomicBoolean(true);
    private volatile int keyStatus = 200;
    private final @NonNull BackendApplication application;

    /** Bind only a fresh loopback fake JWKS listener and construct actual public validators. */
    public ProviderFixture() throws IOException {
        verifyCoreOrigin();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.setExecutor(this.executor);
        this.server.createContext("/google", exchange -> { this.googleFetches.incrementAndGet(); serve(exchange, GOOGLE, "google"); });
        this.server.createContext("/apple", exchange -> { this.appleFetches.incrementAndGet(); serve(exchange, APPLE, "apple"); });
        this.server.createContext("/attacker", exchange -> { this.attackerFetches.incrementAndGet(); serve(exchange, OTHER, "attacker"); });
        this.server.start();
        var config = new BackendApplication.Configuration(URI.create("https://app.example"),
                "web-client.apps.googleusercontent.com", "com.example.native", "company.example", 128, 65_536);
        var accounts = new BackendApplication.Accounts() {
            @Override public @NonNull Optional<BackendApplication.@NonNull Account> findAndAuthorizeLogin(
                    @NonNull String issuer, @NonNull String subject, @NonNull Duration remaining) {
                lookups.incrementAndGet();
                boolean known = issuer.equals(ProviderTokens.GOOGLE) && subject.equals("google-sub")
                        || issuer.equals(ProviderTokens.APPLE) && subject.equals("apple-sub");
                return policy.get() && known ? Optional.of(new BackendApplication.Account("alice", "tenant")) : Optional.empty();
            }
            @Override public boolean authorize(BackendApplication.@NonNull Account account,
                    @NonNull String tenant, @NonNull String id, @NonNull Duration remaining) {
                authorizations.incrementAndGet();
                return policy.get() && account.tenant().equals(tenant) && account.id().equals(id);
            }
        };
        var tokens = new ProviderTokens(config, source("google"), source("google"), source("apple"), this.clock);
        this.application = new BackendApplication(config, accounts,
                (provider, peer, remaining) -> this.admission.get(), this.clock, System::nanoTime, tokens);
    }

    public @NonNull BackendApplication application() { return this.application; }

    /** Protected fixture control; deliberately independent of browser/native application routes. */
    public @NonNull JsonObject control(@NonNull String command) {
        switch (command) {
            case "deny" -> this.policy.set(false);
            case "allow" -> this.policy.set(true);
            case "admission-deny" -> this.admission.set(false);
            case "admission-allow" -> this.admission.set(true);
            case "outage" -> { this.clock.advance(); this.keyStatus = 503; }
            case "state" -> { }
            default -> throw new IllegalArgumentException("Unknown fixture control");
        }
        return JsonObject.builder().put("core_origin_verified", true).put("google_fetches", this.googleFetches.longValue())
                .put("apple_fetches", this.appleFetches.longValue()).put("attacker_fetches", this.attackerFetches.longValue())
                .put("lookups", this.lookups.longValue()).put("authorizations", this.authorizations.longValue())
                .put("attempts", (long) this.application.retainedAttempts())
                .put("sessions", (long) this.application.retainedSessions()).build();
    }

    /** Sign synthetic hostile/control tokens with no real account or provider private key. */
    public @NonNull JsonObject token(@NonNull String provider, @NonNull String nonce, @NonNull String mode) {
        if (!nonce.matches("[A-Za-z0-9_-]{43}") || !(provider.equals("google") || provider.equals("apple")))
            throw new IllegalArgumentException("Invalid fixture input");
        boolean google = provider.equals("google");
        Instant now = this.clock.instant();
        Map<String, JsonValue> claims = new LinkedHashMap<>(JsonObject.builder()
                .put("iss", google ? ProviderTokens.GOOGLE : ProviderTokens.APPLE)
                .put("aud", google ? "web-client.apps.googleusercontent.com" : "com.example.native")
                .put("sub", google ? "google-sub" : "apple-sub").put("iat", now.getEpochSecond())
                .put("exp", now.plusSeconds(300).getEpochSecond()).put("nonce", nonce)
                .put("hd", "company.example").build().getMembers());
        JsonObject.Builder header = JsonObject.builder().put("alg", "RS256").put("kid", provider);
        KeyPair signingKey = google ? GOOGLE : APPLE;
        switch (mode) {
            case "valid" -> { }
            case "legacy-issuer" -> claims.put("iss", com.revetsec.json.JsonString.fromValue(ProviderTokens.GOOGLE_LEGACY));
            case "wrong-issuer" -> claims.put("iss", com.revetsec.json.JsonString.fromValue("https://attacker.invalid"));
            case "wrong-audience" -> claims.put("aud", com.revetsec.json.JsonString.fromValue("attacker-client"));
            case "wrong-nonce" -> claims.put("nonce", com.revetsec.json.JsonString.fromValue("wrong"));
            case "wrong-presenter" -> claims.put("azp", com.revetsec.json.JsonString.fromValue("attacker-client"));
            case "wrong-domain" -> claims.put("hd", com.revetsec.json.JsonString.fromValue("attacker.example"));
            case "unmapped" -> claims.put("sub", com.revetsec.json.JsonString.fromValue("unmapped-sub"));
            case "expired" -> claims.put("exp", com.revetsec.json.JsonNumber.fromValue(now.getEpochSecond()));
            case "signature" -> signingKey = OTHER;
            case "jku" -> header.put("jku", uri("attacker").toString());
            default -> throw new IllegalArgumentException("Invalid fixture mutation");
        }
        return JsonObject.builder().put("token", sign(signingKey, header.build().toJson(),
                JsonObject.fromMembers(claims).toJson())).build();
    }

    private static void verifyCoreOrigin() throws IOException {
        try {
            Path expected = Path.of(System.getenv("REVETSEC_PROVIDER_CORE_JAR")).toRealPath();
            Path actual = Path.of(com.revetsec.jose.JwtValidator.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).toRealPath();
            if (!actual.equals(expected) || Files.size(actual) > 16_777_216
                    || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual)))
                    .equals(System.getenv("REVETSEC_PROVIDER_CORE_SHA256")))
                throw new IOException("Selected core origin mismatch");
        } catch (java.net.URISyntaxException | GeneralSecurityException | RuntimeException failure) {
            throw new IOException("Selected core origin unavailable");
        }
    }
    private @NonNull RemoteJwksSource source(@NonNull String path) {
        return RemoteJwksSource.withUri(uri(path)).allowInsecureLoopback(true).clock(this.clock)
                .requestTimeout(Duration.ofSeconds(1)).maximumKeys(8).maximumResponseBytes(65_536)
                .maximumStaleness(Duration.ZERO).build();
    }
    private @NonNull URI uri(@NonNull String path) {
        return URI.create("http://127.0.0.1:" + this.server.getAddress().getPort() + '/' + path);
    }
    private void serve(com.sun.net.httpserver.@NonNull HttpExchange exchange,
            @NonNull KeyPair pair, @NonNull String kid) throws IOException {
        RSAPublicKey key = (RSAPublicKey) pair.getPublic();
        String body = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"" + kid + "\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\""
                + unsigned(key.getModulus()) + "\",\"e\":\"" + unsigned(key.getPublicExponent()) + "\"}]}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Cache-Control", "max-age=60");
        exchange.getResponseHeaders().set("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(this.clock.instant().atZone(ZoneOffset.UTC)));
        exchange.sendResponseHeaders(this.keyStatus, bytes.length);
        try (var output = exchange.getResponseBody()) { output.write(bytes); }
        exchange.close();
    }
    private static @NonNull String unsigned(java.math.@NonNull BigInteger value) {
        byte[] bytes = value.toByteArray();
        return b64(bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
    }
    private static @NonNull String b64(byte @NonNull [] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private static @NonNull KeyPair key(@NonNull String label) {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(label.getBytes(StandardCharsets.US_ASCII));
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048, random);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException unavailable) { throw new ExceptionInInitializerError(unavailable); }
    }
    private static @NonNull String sign(@NonNull KeyPair pair, @NonNull String header, @NonNull String payload) {
        try {
            String input = b64(header.getBytes(StandardCharsets.UTF_8)) + '.' + b64(payload.getBytes(StandardCharsets.UTF_8));
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(pair.getPrivate()); signature.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + '.' + b64(signature.sign());
        } catch (GeneralSecurityException unavailable) { throw new IllegalStateException("Fixture signing unavailable"); }
    }
    @Override public void close() { this.server.stop(0); this.executor.shutdownNow(); }
    @Override public @NonNull String toString() { return "ProviderFixture{test-only, redacted}"; }

    private static final class MutableClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> value = new AtomicReference<>(Instant.parse("2026-11-05T12:00:00Z"));
        private void advance() { this.value.updateAndGet(value -> value.plusSeconds(61)); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(instant(), zone); }
        @Override public @NonNull Instant instant() { return this.value.get(); }
    }
}
