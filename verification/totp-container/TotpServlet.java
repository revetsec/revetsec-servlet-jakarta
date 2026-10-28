/*
 * Copyright 2026 Revetware LLC.
 *
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
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.totp.InMemoryTotpStore;
import com.revetsec.totp.RecoveryCodeRotationResult;
import com.revetsec.totp.RecoveryCodeUse;
import com.revetsec.totp.RecoveryCodeUseResult;
import com.revetsec.totp.RecoveryCodes;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpEnrollment;
import com.revetsec.totp.TotpEnrollmentCancellationResult;
import com.revetsec.totp.TotpEnrollmentOptions;
import com.revetsec.totp.TotpEnrollmentRequestResult;
import com.revetsec.totp.TotpEnrollmentResult;
import com.revetsec.totp.TotpFactorRemovalResult;
import com.revetsec.totp.TotpNamespaceInitializationResult;
import com.revetsec.totp.TotpRecoveryContext;
import com.revetsec.totp.TotpRecoveryGate;
import com.revetsec.totp.TotpStatus;
import com.revetsec.totp.TotpStatusResult;
import com.revetsec.totp.TotpStore;
import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreWrite;
import com.revetsec.totp.TotpVerification;
import com.revetsec.totp.TotpVerificationResult;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Private, single-process HTTP qualification host; its primary-authentication route is synthetic. */
@ThreadSafe
public final class TotpServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final @NonNull String ACCOUNT = "fixture-account";
    private static final @NonNull String EPOCH = "fixture-epoch";
    private static final @NonNull String ORIGIN = "https://login.example.com";
    private static final @NonNull SecureRandom RANDOM = new SecureRandom();
    private final @NonNull Map<@NonNull String, @NonNull Session> sessions = new HashMap<>();
    private final @NonNull Gate gate = new Gate();
    private final @NonNull TestClock clock = new TestClock();
    private final @NonNull FaultStore store;
    private final @NonNull TotpAuthenticator totp;
    private @NonNull String factorId = "";
    private @NonNull String batchId = "";

    public TotpServlet() {
        byte[] material = new byte[32];
        RANDOM.nextBytes(material);
        this.store = new FaultStore(InMemoryTotpStore.withNamespace("fixture-totp", EPOCH).build());
        this.totp = TotpAuthenticator.withIssuer("Fixture")
                .credentialNamespace("fixture-totp").recoveryEpoch(EPOCH).store(this.store)
                .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("fixture-key",
                        Base64.getEncoder().encodeToString(material))).build())
                .clock(this.clock).recoveryGate(this.gate).build();
        if (!(this.totp.initializeNamespaceResult() instanceof TotpNamespaceInitializationResult.Initialized))
            throw new IllegalStateException("Fixture namespace did not initialize");
        this.gate.provisioning = false;
    }

    @Override protected void doGet(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException { handle(request, response); }
    @Override protected void doHead(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException { handle(request, response); }
    @Override protected void doPost(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException { handle(request, response); }

    private synchronized void handle(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        if (!privateCredential(request)) { send(response, 401, error("Request rejected"), false); return; }
        String path = request.getPathInfo();
        if (path == null) { send(response, 404, error("Request rejected"), false); return; }
        if (path.equals("/health")) { send(response, 200, JsonObject.builder().put("ready", true).build(), false); return; }
        if (path.equals("/session/start")) { startSession(request, response); return; }
        if (path.equals("/test/unknown")) {
            if (!post(request, response)) return;
            this.store.loseSecondCommitAcknowledgement();
            send(response, 204, null, false); return;
        }
        if (path.equals("/test/close")) {
            if (!post(request, response)) return;
            this.gate.open = false;
            send(response, 204, null, false); return;
        }
        if (path.equals("/test/open")) {
            if (!post(request, response)) return;
            this.gate.open = true;
            send(response, 204, null, false); return;
        }
        if (path.equals("/test/advance")) {
            if (!post(request, response)) return;
            this.clock.advance(); send(response, 204, null, false); return;
        }
        if (path.equals("/test/expire-on-close")) {
            if (!post(request, response)) return;
            this.gate.expireOnAppClose = true; send(response, 204, null, false); return;
        }
        boolean head = request.getMethod().equals("HEAD");
        if (path.equals("/status")) {
            if (!request.getMethod().equals("GET") && !head) { method(response, "GET, HEAD"); return; }
        } else if (!post(request, response)) return;
        long startedAt = this.gate.monotonicNanos();
        BufferedResponse buffered = new BufferedResponse(response);
        boolean current = false;
        try (Gate.AppPermit permit = this.gate.appPermit(Duration.ofSeconds(10))) {
            if (permit != null && permit.isCurrent()) {
                dispatchProtected(path, request, buffered, head);
                current = permit.isCurrent();
            }
        }
        long elapsed = this.gate.monotonicNanos() - startedAt;
        if (!current || !this.gate.open || elapsed < 0 || elapsed >= Duration.ofSeconds(10).toNanos())
            send(response, 503, error("Temporarily unavailable"), head);
        else buffered.writeTo(response);
    }

    private void dispatchProtected(@NonNull String path, @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response, boolean head) throws IOException {
            Session session = browserSession(request);
            if (session == null || (!path.equals("/status") && !path.equals("/enroll")
                    && !path.equals("/replace") && !path.equals("/cancel")
                    && !path.equals("/confirm") && !path.equals("/rotate")
                    && !path.equals("/remove") && !path.equals("/login")
                    && !path.equals("/recovery"))) {
                send(response, 403, error("Request rejected"), head); return;
            }
            switch (path) {
                case "/enroll", "/replace" -> enroll(session, path.equals("/replace"), response);
                case "/confirm" -> confirm(session, request, response);
                case "/login", "/recovery" -> login(session, request, response, path.equals("/recovery"));
                case "/status" -> status(response, head);
                case "/cancel" -> cancel(session, response);
                case "/rotate" -> rotate(session, response);
                case "/remove" -> remove(session, response);
                default -> throw new IllegalStateException("Unreachable TOTP route");
            }
    }

    private void startSession(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        if (!get(request, response)) return;
        if (!this.gate.open) { send(response, 503, error("Temporarily unavailable"), false); return; }
        String token = random();
        Session session = new Session(token, random(), random(), "PRIMARY");
        this.sessions.put(token, session);
        sessionHeaders(response, session);
        send(response, 200, JsonObject.builder().put("primaryPending", true).build(), false);
    }

    private void enroll(@NonNull Session session, boolean replacement,
            @NonNull HttpServletResponse response) throws IOException {
        if (replacement ? !session.method.equals("TOTP") || this.factorId.isEmpty()
                : !session.method.equals("PRIMARY") || !this.factorId.isEmpty()) {
            send(response, 403, error("Request rejected"), false); return;
        }
        TotpEnrollmentOptions.Builder options = TotpEnrollmentOptions.withAccountId(ACCOUNT)
                .accountName("fixture-account");
        if (replacement) options.replacingFactorId(this.factorId);
        TotpEnrollmentRequestResult result = this.totp.beginEnrollmentResult(options.build(), session.binding);
        if (result instanceof TotpEnrollmentRequestResult.Prepared prepared) {
            TotpEnrollment enrollment = prepared.getEnrollment();
            session.enrollmentId = enrollment.getEnrollmentId();
            send(response, 200, JsonObject.builder()
                    .put("enrollmentId", enrollment.getEnrollmentId())
                    .put("manualEntryKey", enrollment.getManualEntryKey())
                    .put("provisioningUri", enrollment.getProvisioningUri()).build(), false);
        } else if (result instanceof TotpEnrollmentRequestResult.Throttled throttled) {
            throttle(response, throttled.getRetryAfter());
        } else if (result instanceof TotpEnrollmentRequestResult.Unavailable
                || result instanceof TotpEnrollmentRequestResult.Indeterminate) {
            send(response, 503, error("Temporarily unavailable"), false);
        } else send(response, 403, error("Request rejected"), false);
    }

    private void confirm(@NonNull Session session, @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        if (session.enrollmentId.isEmpty() || (!session.method.equals("PRIMARY") && !session.method.equals("TOTP"))) {
            send(response, 403, error("Request rejected"), false); return;
        }
        String code = codeBody(request, response);
        if (code == null) return;
        TotpEnrollmentResult result = this.totp.confirmEnrollmentResult(ACCOUNT, session.enrollmentId, code, session.binding);
        if (result instanceof TotpEnrollmentResult.Succeeded success) {
            this.factorId = success.getFactor().getFactorId();
            this.batchId = success.getRecoveryCodes().getBatchId();
            session.enrollmentId = "";
            send(response, 200, codes(success.getRecoveryCodes()), false);
        } else if (result instanceof TotpEnrollmentResult.Throttled throttled) {
            throttle(response, throttled.getRetryAfter());
        } else if (result instanceof TotpEnrollmentResult.Unavailable
                || result instanceof TotpEnrollmentResult.Indeterminate) {
            send(response, 503, error("Temporarily unavailable"), false);
        } else send(response, 403, error("Request rejected"), false);
    }

    private void login(@NonNull Session session, @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response, boolean recovery) throws IOException {
        if (!session.method.equals("PRIMARY") || this.factorId.isEmpty()) {
            send(response, 403, error("Request rejected"), false); return;
        }
        String code = codeBody(request, response);
        if (code == null) return;
        if (recovery) {
            RecoveryCodeUseResult result = this.totp.consumeRecoveryCodeResult(ACCOUNT, code, session.binding);
            if (result instanceof RecoveryCodeUseResult.Succeeded success) {
                RecoveryCodeUse proof = success.getUse();
                if (proof.getRecoveryEpoch().equals(EPOCH) && proof.getAccountId().equals(ACCOUNT)
                        && proof.getOperationBinding().equals(session.binding)
                        && proof.getFactorId().equals(this.factorId)) {
                    rotateSession(session, response, "RECOVERY_CODE");
                    send(response, 200, JsonObject.builder().put("recoverySession", true).build(), false);
                } else send(response, 503, error("Temporarily unavailable"), false);
            } else if (result instanceof RecoveryCodeUseResult.Throttled throttled) {
                throttle(response, throttled.getRetryAfter());
            } else if (result instanceof RecoveryCodeUseResult.Unavailable
                    || result instanceof RecoveryCodeUseResult.Indeterminate) {
                send(response, 503, error("Temporarily unavailable"), false);
            } else send(response, 403, error("Request rejected"), false);
        } else {
            TotpVerificationResult result = this.totp.verifyResult(ACCOUNT, code, session.binding);
            if (result instanceof TotpVerificationResult.Succeeded success) {
                TotpVerification proof = success.getVerification();
                if (proof.getRecoveryEpoch().equals(EPOCH) && proof.getAccountId().equals(ACCOUNT)
                        && proof.getOperationBinding().equals(session.binding)
                        && proof.getFactorId().equals(this.factorId)) {
                    rotateSession(session, response, "TOTP");
                    send(response, 200, JsonObject.builder().put("authenticated", true).build(), false);
                } else send(response, 503, error("Temporarily unavailable"), false);
            } else if (result instanceof TotpVerificationResult.Throttled throttled) {
                throttle(response, throttled.getRetryAfter());
            } else if (result instanceof TotpVerificationResult.Unavailable
                    || result instanceof TotpVerificationResult.Indeterminate) {
                send(response, 503, error("Temporarily unavailable"), false);
            } else send(response, 403, error("Request rejected"), false);
        }
    }

    private void status(@NonNull HttpServletResponse response, boolean head) throws IOException {
        TotpStatusResult result = this.totp.getStatusResult(ACCOUNT);
        if (result instanceof TotpStatusResult.Present present) {
            TotpStatus status = present.getStatus();
            send(response, 200, JsonObject.builder()
                    .put("active", status.getActiveFactor().isPresent())
                    .put("pending", status.getPendingEnrollment().isPresent())
                    .put("remainingRecoveryCodes", status.getRemainingRecoveryCodeCount().longValue()).build(), head);
        } else if (result instanceof TotpStatusResult.Absent) {
            send(response, 200, JsonObject.builder().put("active", false).put("pending", false)
                    .put("remainingRecoveryCodes", 0L).build(), head);
        } else send(response, 503, error("Temporarily unavailable"), head);
    }

    private void cancel(@NonNull Session session, @NonNull HttpServletResponse response) throws IOException {
        if (session.enrollmentId.isEmpty()) { send(response, 403, error("Request rejected"), false); return; }
        TotpEnrollmentCancellationResult result = this.totp.cancelEnrollmentResult(
                ACCOUNT, session.enrollmentId, session.binding);
        if (result instanceof TotpEnrollmentCancellationResult.Succeeded) {
            session.enrollmentId = "";
            send(response, 200, JsonObject.builder().put("cancelled", true).build(), false);
        } else if (result instanceof TotpEnrollmentCancellationResult.Unavailable
                || result instanceof TotpEnrollmentCancellationResult.Indeterminate) {
            send(response, 503, error("Temporarily unavailable"), false);
        } else send(response, 403, error("Request rejected"), false);
    }

    private void rotate(@NonNull Session session, @NonNull HttpServletResponse response) throws IOException {
        if (!session.method.equals("TOTP") || this.factorId.isEmpty() || this.batchId.isEmpty()) {
            send(response, 403, error("Request rejected"), false); return;
        }
        RecoveryCodeRotationResult result = this.totp.rotateRecoveryCodesResult(ACCOUNT, this.factorId, this.batchId);
        if (result instanceof RecoveryCodeRotationResult.Succeeded success) {
            this.batchId = success.getRecoveryCodes().getBatchId();
            send(response, 200, codes(success.getRecoveryCodes()), false);
        } else if (result instanceof RecoveryCodeRotationResult.Unavailable
                || result instanceof RecoveryCodeRotationResult.Indeterminate) {
            send(response, 503, error("Temporarily unavailable"), false);
        } else send(response, 403, error("Request rejected"), false);
    }

    private void remove(@NonNull Session session, @NonNull HttpServletResponse response) throws IOException {
        if (!session.method.equals("TOTP") || this.factorId.isEmpty()) {
            send(response, 403, error("Request rejected"), false); return;
        }
        TotpFactorRemovalResult result = this.totp.removeFactorResult(ACCOUNT, this.factorId);
        if (result instanceof TotpFactorRemovalResult.Succeeded) {
            this.factorId = ""; this.batchId = "";
            this.sessions.clear();
            send(response, 200, JsonObject.builder().put("removed", true).build(), false);
        } else if (result instanceof TotpFactorRemovalResult.Unavailable
                || result instanceof TotpFactorRemovalResult.Indeterminate) {
            send(response, 503, error("Temporarily unavailable"), false);
        } else send(response, 403, error("Request rejected"), false);
    }

    private @Nullable Session browserSession(@NonNull HttpServletRequest request) {
        String cookie = single(request, "Cookie");
        String origin = single(request, "Origin");
        String csrf = single(request, "X-Fixture-Csrf");
        if (cookie == null || origin == null || csrf == null || !origin.equals(ORIGIN)
                || !cookie.startsWith("totp_session=") || cookie.indexOf(';') >= 0
                || request.getQueryString() != null) return null;
        Session session = this.sessions.get(cookie.substring("totp_session=".length()));
        return session != null && session.csrf.equals(csrf) ? session : null;
    }

    private static @Nullable String codeBody(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        if (!"text/plain; charset=UTF-8".equals(single(request, "Content-Type"))) {
            send(response, 415, error("Request rejected"), false); return null;
        }
        byte[] body = request.getInputStream().readNBytes(129);
        if (body.length > 128) { send(response, 413, error("Request rejected"), false); return null; }
        for (byte value : body) if (value < 0x20 || value > 0x7e) {
            send(response, 400, error("Request rejected"), false); return null;
        }
        return new String(body, StandardCharsets.US_ASCII);
    }

    private static @Nullable String single(@NonNull HttpServletRequest request, @NonNull String name) {
        Enumeration<@NonNull String> values = request.getHeaders(name);
        if (values == null || !values.hasMoreElements()) return null;
        String value = values.nextElement();
        return values.hasMoreElements() ? null : value;
    }

    private static boolean privateCredential(@NonNull HttpServletRequest request) {
        String expected = System.getProperty("fixture.credential", "");
        String supplied = single(request, "X-Fixture-Credential");
        return !expected.isEmpty() && expected.equals(supplied);
    }

    private static boolean get(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        if (request.getMethod().equals("GET")) return true;
        method(response, "GET"); return false;
    }
    private static boolean post(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        if (request.getMethod().equals("POST")) return true;
        method(response, "POST"); return false;
    }
    private static void method(@NonNull HttpServletResponse response, @NonNull String allow) throws IOException {
        response.setHeader("Allow", allow); send(response, 405, error("Request rejected"), false);
    }
    private static @NonNull JsonObject error(@NonNull String value) {
        return JsonObject.builder().put("error", value).build();
    }
    private static @NonNull JsonObject codes(@NonNull RecoveryCodes value) {
        return JsonObject.builder().put("batchId", value.getBatchId())
                .put("codes", JsonArray.fromElements(value.getCodes().stream()
                        .map(JsonString::fromValue).toList())).build();
    }
    private static void throttle(@NonNull HttpServletResponse response,
            @NonNull Duration retryAfter) throws IOException {
        long seconds = Math.max(1L, retryAfter.getSeconds() + (retryAfter.getNano() == 0 ? 0 : 1));
        response.setHeader("Retry-After", Long.toString(seconds));
        send(response, 429, error("Try again later"), false);
    }
    private static void send(@NonNull HttpServletResponse response, int status,
            @Nullable JsonObject body, boolean head) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("X-Content-Type-Options", "nosniff");
        if (body != null) {
            byte[] bytes = body.toJson().getBytes(StandardCharsets.UTF_8);
            response.setContentType("application/json; charset=UTF-8");
            response.setContentLength(bytes.length);
            if (!head) response.getOutputStream().write(bytes);
        }
    }
    private static @NonNull String random() {
        byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private static void sessionHeaders(@NonNull HttpServletResponse response, @NonNull Session session) {
        response.setHeader("Set-Cookie", "totp_session=" + session.token
                + "; Path=/totp; Secure; HttpOnly; SameSite=Strict");
        response.setHeader("X-Fixture-Csrf", session.csrf);
    }
    private void rotateSession(@NonNull Session old, @NonNull HttpServletResponse response,
            @NonNull String method) {
        this.sessions.remove(old.token);
        Session fresh = new Session(random(), random(), random(), method);
        this.sessions.put(fresh.token, fresh);
        sessionHeaders(response, fresh);
    }
    private static final class Session {
        private final @NonNull String token;
        private final @NonNull String csrf;
        private final @NonNull String binding;
        private final @NonNull String method;
        private @NonNull String enrollmentId = "";
        private Session(@NonNull String token, @NonNull String csrf, @NonNull String binding,
                @NonNull String method) {
            this.token = token; this.csrf = csrf; this.binding = binding; this.method = method;
        }
    }
    private static final class BufferedResponse extends HttpServletResponseWrapper {
        private final @NonNull Map<@NonNull String, @NonNull String> headers = new LinkedHashMap<>();
        private final @NonNull ByteArrayOutputStream body = new ByteArrayOutputStream();
        private final @NonNull ServletOutputStream output = new ServletOutputStream() {
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(@NonNull WriteListener listener) {
                throw new UnsupportedOperationException("Synchronous fixture only");
            }
            @Override public void write(int value) { BufferedResponse.this.body.write(value); }
        };
        private int status = 200;
        private BufferedResponse(@NonNull HttpServletResponse actual) { super(actual); }
        @Override public void setStatus(int value) { this.status = value; }
        @Override public void setHeader(@NonNull String name, @NonNull String value) {
            this.headers.put(name, value);
        }
        @Override public void setContentType(@NonNull String value) { setHeader("Content-Type", value); }
        @Override public void setContentLength(int length) { setHeader("Content-Length", Integer.toString(length)); }
        @Override public @NonNull ServletOutputStream getOutputStream() { return this.output; }
        private void writeTo(@NonNull HttpServletResponse actual) throws IOException {
            actual.setStatus(this.status);
            for (Map.Entry<String, String> field : this.headers.entrySet())
                actual.setHeader(field.getKey(), field.getValue());
            actual.getOutputStream().write(this.body.toByteArray());
        }
    }
    /** Intentionally volatile fixture fault: delegate COMMIT, then lose its second acknowledgement. */
    private static final class FaultStore implements TotpStore {
        private final @NonNull TotpStore delegate;
        private final @NonNull AtomicInteger remaining = new AtomicInteger();
        private FaultStore(@NonNull TotpStore delegate) { this.delegate = delegate; }
        private void loseSecondCommitAcknowledgement() { this.remaining.set(2); }
        @Override public @NonNull TotpStoreReadResult read(
                @NonNull Set<@NonNull TotpStoreKey> keys, @NonNull Duration budget) {
            return this.delegate.read(keys, budget);
        }
        @Override public @NonNull TotpStoreCommitResult compareAndCommit(
                @NonNull TotpStoreWrite write, @NonNull Duration budget) {
            TotpStoreCommitResult result = this.delegate.compareAndCommit(write, budget);
            if (result == TotpStoreCommitResult.COMMITTED && this.remaining.get() > 0
                    && this.remaining.decrementAndGet() == 0) return TotpStoreCommitResult.UNKNOWN;
            return result;
        }
    }
    /** Only a disposable, one-JVM test gate; no cross-host recovery or restore safety. */
    private static final class Gate implements TotpRecoveryGate {
        private volatile boolean open = true;
        private volatile boolean provisioning = true;
        private volatile boolean expireOnAppClose;
        private final @NonNull AtomicLong monotonicOffset = new AtomicLong();
        private long monotonicNanos() { return System.nanoTime() + this.monotonicOffset.get(); }
        @Override public @Nullable Permit acquire(@NonNull TotpRecoveryContext context,
                @NonNull Duration budget) {
            if (!this.open || (context.getPurpose() == TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE
                    && !this.provisioning)) return null;
            return new AppPermit(this, budget, false);
        }
        private @Nullable AppPermit appPermit(@NonNull Duration budget) {
            return this.open ? new AppPermit(this, budget, true) : null;
        }
        private static final class AppPermit implements TotpRecoveryGate.Permit {
            private final @NonNull Gate gate;
            private final long deadline;
            private final boolean application;
            private boolean closed;
            private AppPermit(@NonNull Gate gate, @NonNull Duration budget, boolean application) {
                this.gate = gate; this.application = application;
                this.deadline = gate.monotonicNanos() + budget.toNanos();
            }
            @Override public @NonNull Boolean isCurrent() {
                return !this.closed && this.gate.open && this.gate.monotonicNanos() < this.deadline;
            }
            @Override public void close() {
                if (!this.closed && this.application && this.gate.expireOnAppClose) {
                    this.gate.expireOnAppClose = false;
                    this.gate.monotonicOffset.addAndGet(Duration.ofSeconds(11).toNanos());
                }
                this.closed = true;
            }
        }
    }
    private static final class TestClock extends Clock {
        private final @NonNull AtomicLong seconds = new AtomicLong(
                Instant.parse("2026-10-16T12:00:00Z").getEpochSecond());
        private void advance() { this.seconds.addAndGet(30); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
            if (!zone.equals(ZoneOffset.UTC)) throw new IllegalArgumentException("UTC fixture only");
            return this;
        }
        @Override public @NonNull Instant instant() { return Instant.ofEpochSecond(this.seconds.get()); }
    }
}
