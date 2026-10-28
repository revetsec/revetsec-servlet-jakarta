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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
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
import com.revetsec.totp.TotpFactor;
import com.revetsec.totp.TotpFactorRemovalResult;
import com.revetsec.totp.TotpPendingEnrollment;
import com.revetsec.totp.TotpStatus;
import com.revetsec.totp.TotpStatusResult;
import com.revetsec.totp.TotpVerification;
import com.revetsec.totp.TotpVerificationResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Application-owned Servlet 6.1 TOTP integration. Register an instance at {@code /totp/*} and
 * inject the application's durable store, admission, session and coordinated recovery controller.
 * This is a compilable cookbook source, not a published Revetsec adapter API.
 */
@ThreadSafe
public final class ServletTotpRecipe extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final @NonNull Duration REQUEST_BUDGET = Duration.ofSeconds(10);
    private final @NonNull TotpAuthenticator totp;
    private final @NonNull ApplicationSecurity security;
    private final @NonNull String recoveryEpoch;

    /** The authenticator and security implementation must share a coordinated recovery fence. */
    public ServletTotpRecipe(@NonNull TotpAuthenticator totp, @NonNull ApplicationSecurity security) {
        this.totp = Objects.requireNonNull(totp);
        this.security = Objects.requireNonNull(security);
        this.recoveryEpoch = totp.getRecoveryEpoch();
    }

    @Override protected void doGet(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        dispatch(request, response);
    }

    @Override protected void doHead(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        // Write our own HEAD response: neither the body nor the enrollment secret is emitted.
        dispatch(request, response);
    }

    @Override protected void doPost(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        dispatch(request, response);
    }

    private void dispatch(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response) throws IOException {
        String path = request.getPathInfo();
        if (path == null) { write(response, request, json(404, "Unknown route")); return; }
        boolean status = path.equals("/status");
        if (status ? !(request.getMethod().equals("GET") || request.getMethod().equals("HEAD"))
                   : !request.getMethod().equals("POST")) {
            response.setHeader("Allow", status ? "GET, HEAD" : "POST");
            write(response, request, json(405, "Unsupported method"));
            return;
        }
        Prepared prepared = switch (path) {
            case "/enroll" -> admitted(request, () -> beginEnrollment(request, false));
            case "/replace" -> admitted(request, () -> beginEnrollment(request, true));
            case "/confirm" -> admitted(request, () -> confirmEnrollment(request));
            case "/login" -> admitted(request, () -> verifyTotp(request));
            case "/recovery" -> admitted(request, () -> useRecoveryCode(request));
            case "/rotate" -> admitted(request, () -> rotateRecoveryCodes(request));
            case "/remove" -> admitted(request, () -> removeFactor(request));
            case "/cancel" -> admitted(request, () -> cancelEnrollment(request));
            case "/status" -> admitted(request, () -> status(request));
            default -> json(404, "Unknown route");
        };
        write(response, request, prepared);
    }

    private @NonNull Prepared beginEnrollment(@NonNull HttpServletRequest request, boolean replacement)
            throws IOException {
        EnrollmentContext context = this.security.admitEnrollment(request, replacement);
        if (context == null) return denied();
        TotpEnrollmentOptions.Builder options = TotpEnrollmentOptions.withAccountId(context.getAccountId())
                .accountName(context.getAccountLabel());
        String replacing = context.getReplacingFactorId().orElse(null);
        if (replacement) {
            if (replacing == null) return denied();
            options = options.replacingFactorId(replacing);
        } else if (replacing != null) return denied();
        TotpEnrollmentRequestResult result = this.totp.beginEnrollmentResult(
                options.build(), context.getBrowserBinding());
        if (result instanceof TotpEnrollmentRequestResult.Prepared prepared) {
            TotpEnrollment enrollment = prepared.getEnrollment();
            // Save identifiers, not the setup secret. An uncertain save withholds that secret.
            if (!this.security.rememberEnrollment(context, enrollment.getEnrollmentId(),
                    enrollment.getFactorId(), enrollment.getExpiresAt())) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return json(200, JsonObject.builder()
                    .put("enrollmentId", enrollment.getEnrollmentId())
                    .put("factorId", enrollment.getFactorId())
                    .put("expiresAt", enrollment.getExpiresAt().toString())
                    .put("provisioningUri", enrollment.getProvisioningUri())
                    .put("manualEntryKey", enrollment.getManualEntryKey()).build());
        }
        if (result instanceof TotpEnrollmentRequestResult.Throttled throttled)
            return throttled(throttled.getRetryAfter());
        if (result instanceof TotpEnrollmentRequestResult.Indeterminate) {
            this.security.requireReconciliation(context);
            return unavailable();
        }
        return result instanceof TotpEnrollmentRequestResult.Unavailable ? unavailable() : denied();
    }

    private @NonNull Prepared confirmEnrollment(@NonNull HttpServletRequest request) throws IOException {
        EnrollmentSubmission input = this.security.admitEnrollmentConfirmation(request);
        if (input == null) return denied();
        TotpEnrollmentResult result = this.totp.confirmEnrollmentResult(input.getAccountId(),
                input.getEnrollmentId(), input.getCode(), input.getBrowserBinding());
        if (result instanceof TotpEnrollmentResult.Succeeded success) {
            if (!this.recoveryEpoch.equals(success.getFactor().getRecoveryEpoch())
                    || !this.security.completeEnrollment(input, success.getFactor(),
                            success.getRecoveryCodes().getBatchId())) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            return json(200, JsonObject.builder().put("factor", factor(success.getFactor()))
                    .put("recoveryCodes", recoveryCodes(success.getRecoveryCodes())).build());
        }
        if (result instanceof TotpEnrollmentResult.Throttled throttled)
            return throttled(throttled.getRetryAfter());
        if (result instanceof TotpEnrollmentResult.Indeterminate) {
            this.security.requireReconciliation(input);
            return unavailable();
        }
        return result instanceof TotpEnrollmentResult.Unavailable ? unavailable() : denied();
    }

    private @NonNull Prepared verifyTotp(@NonNull HttpServletRequest request) throws IOException {
        LoginSubmission input = this.security.admitTotpLogin(request);
        if (input == null) return denied();
        TotpVerificationResult result = this.totp.verifyResult(input.getAccountId(),
                input.getCode(), input.getOperationBinding());
        if (result instanceof TotpVerificationResult.Succeeded success) {
            TotpVerification proof = success.getVerification();
            if (!this.recoveryEpoch.equals(proof.getRecoveryEpoch())) return unavailable();
            LoginCompletion completion = this.security.completeTotpLogin(input, proof);
            if (completion == null) return unavailable();
            return json(200, JsonObject.builder().put("authenticated", true).build())
                    .withCookies(completion.getSetCookieHeaders());
        }
        if (result instanceof TotpVerificationResult.Throttled throttled)
            return throttled(throttled.getRetryAfter());
        return result instanceof TotpVerificationResult.Unavailable
                || result instanceof TotpVerificationResult.Indeterminate ? unavailable() : denied();
    }

    private @NonNull Prepared useRecoveryCode(@NonNull HttpServletRequest request) throws IOException {
        LoginSubmission input = this.security.admitRecoveryLogin(request);
        if (input == null) return denied();
        RecoveryCodeUseResult result = this.totp.consumeRecoveryCodeResult(input.getAccountId(),
                input.getCode(), input.getOperationBinding());
        if (result instanceof RecoveryCodeUseResult.Succeeded success) {
            RecoveryCodeUse proof = success.getUse();
            if (!this.recoveryEpoch.equals(proof.getRecoveryEpoch())) return unavailable();
            LoginCompletion completion = this.security.completeRecoveryLogin(input, proof);
            if (completion == null) return unavailable();
            return json(200, JsonObject.builder().put("recoverySession", true).build())
                    .withCookies(completion.getSetCookieHeaders());
        }
        if (result instanceof RecoveryCodeUseResult.Throttled throttled)
            return throttled(throttled.getRetryAfter());
        return result instanceof RecoveryCodeUseResult.Unavailable
                || result instanceof RecoveryCodeUseResult.Indeterminate ? unavailable() : denied();
    }

    private @NonNull Prepared rotateRecoveryCodes(@NonNull HttpServletRequest request) throws IOException {
        RotationContext context = this.security.admitRecoveryRotation(request);
        if (context == null) return denied();
        RecoveryCodeRotationResult result = this.totp.rotateRecoveryCodesResult(context.getAccountId(),
                context.getExpectedFactorId(), context.getExpectedBatchId());
        if (result instanceof RecoveryCodeRotationResult.Succeeded success) {
            RecoveryCodes codes = success.getRecoveryCodes();
            if (!this.security.completeRotation(context, codes.getBatchId())) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return json(200, recoveryCodes(codes));
        }
        if (result instanceof RecoveryCodeRotationResult.Indeterminate) {
            this.security.requireReconciliation(context);
            return unavailable();
        }
        return result instanceof RecoveryCodeRotationResult.Unavailable ? unavailable() : denied();
    }

    private @NonNull Prepared removeFactor(@NonNull HttpServletRequest request) throws IOException {
        RemovalContext context = this.security.admitRemoval(request);
        if (context == null) return denied();
        TotpFactorRemovalResult result = this.totp.removeFactorResult(
                context.getAccountId(), context.getExpectedFactorId());
        if (result instanceof TotpFactorRemovalResult.Succeeded) {
            if (!this.security.completeRemoval(context)) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return json(200, JsonObject.builder().put("removed", true).build());
        }
        if (result instanceof TotpFactorRemovalResult.Indeterminate) {
            this.security.requireReconciliation(context);
            return unavailable();
        }
        return result instanceof TotpFactorRemovalResult.Unavailable ? unavailable() : denied();
    }

    private @NonNull Prepared cancelEnrollment(@NonNull HttpServletRequest request) throws IOException {
        CancellationContext context = this.security.admitCancellation(request);
        if (context == null) return denied();
        TotpEnrollmentCancellationResult result = this.totp.cancelEnrollmentResult(context.getAccountId(),
                context.getEnrollmentId(), context.getBrowserBinding());
        if (result instanceof TotpEnrollmentCancellationResult.Succeeded) {
            if (!this.security.completeCancellation(context)) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return json(200, JsonObject.builder().put("cancelled", true).build());
        }
        if (result instanceof TotpEnrollmentCancellationResult.Indeterminate) {
            this.security.requireReconciliation(context);
            return unavailable();
        }
        return result instanceof TotpEnrollmentCancellationResult.Unavailable ? unavailable() : denied();
    }

    private @NonNull Prepared status(@NonNull HttpServletRequest request) throws IOException {
        ActionContext context = this.security.admitStatus(request);
        if (context == null) return denied();
        TotpStatusResult result = this.totp.getStatusResult(context.getAccountId());
        if (result instanceof TotpStatusResult.Present present)
            return json(200, status(present.getStatus()));
        if (result instanceof TotpStatusResult.Absent)
            return json(200, JsonObject.builder().put("active", false).put("pending", false)
                    .put("remainingRecoveryCodes", 0L).build());
        return unavailable();
    }

    private @NonNull Prepared admitted(@NonNull HttpServletRequest request,
            @NonNull Work work) throws IOException {
        // Keep the same outer recovery permit across core work and the application completion
        // transaction. The permit must nest with the core gate or atomically fence the same epoch.
        long startedAt = System.nanoTime();
        Prepared result = unavailable();
        try (RequestPermit permit = this.security.acquireRequestPermit(request, REQUEST_BUDGET)) {
            if (permit != null && this.recoveryEpoch.equals(permit.getRecoveryEpoch())
                    && permit.isCurrent()) {
                Prepared candidate = work.get();
                if (permit.isCurrent()) result = candidate;
            }
        }
        // Closing can itself exhaust the budget. Check again before releasing secret JSON or a
        // session cookie, even when core and the application transaction both succeeded.
        long elapsed = System.nanoTime() - startedAt;
        return elapsed >= 0 && elapsed < REQUEST_BUDGET.toNanos() ? result : unavailable();
    }

    @FunctionalInterface
    private interface Work {
        @NonNull Prepared get() throws IOException;
    }

    private static @NonNull JsonObject factor(@NonNull TotpFactor factor) {
        return JsonObject.builder().put("factorId", factor.getFactorId())
                .put("recoveryEpoch", factor.getRecoveryEpoch()).build();
    }

    private static @NonNull JsonObject recoveryCodes(@NonNull RecoveryCodes codes) {
        return JsonObject.builder().put("batchId", codes.getBatchId())
                .put("codes", JsonArray.fromElements(codes.getCodes().stream()
                        .map(JsonString::fromValue).toList())).build();
    }

    private static @NonNull JsonObject status(@NonNull TotpStatus status) {
        JsonObject.Builder body = JsonObject.builder().put("active", status.getActiveFactor().isPresent())
                .put("pending", status.getPendingEnrollment().isPresent())
                .put("remainingRecoveryCodes", status.getRemainingRecoveryCodeCount().longValue());
        status.getActiveFactor().ifPresent(value -> body.put("factor", factor(value)));
        status.getRecoveryBatchId().ifPresent(value -> body.put("recoveryBatchId", value));
        TotpPendingEnrollment pending = status.getPendingEnrollment().orElse(null);
        if (pending != null) body.put("pendingEnrollment", JsonObject.builder()
                .put("enrollmentId", pending.getEnrollmentId()).put("factorId", pending.getFactorId())
                .put("expiresAt", pending.getExpiresAt().toString()).build());
        return body.build();
    }

    private static @NonNull Prepared denied() { return json(403, "Request rejected"); }
    private static @NonNull Prepared unavailable() { return json(503, "Temporarily unavailable"); }
    private static @NonNull Prepared throttled(@NonNull Duration retryAfter) {
        long seconds = Math.max(1, retryAfter.getSeconds() + (retryAfter.getNano() == 0 ? 0 : 1));
        return json(429, "Try again later").withRetryAfter(seconds);
    }
    private static @NonNull Prepared json(int status, @NonNull String error) {
        return json(status, JsonObject.builder().put("error", error).build());
    }
    private static @NonNull Prepared json(int status, @NonNull JsonObject body) {
        return new Prepared(status, body.toJson().getBytes(StandardCharsets.UTF_8), List.of(), 0);
    }

    private static void write(@NonNull HttpServletResponse response, @NonNull HttpServletRequest request,
            @NonNull Prepared prepared) throws IOException {
        for (String cookie : prepared.setCookieHeaders) {
            if (cookie.indexOf('\r') >= 0 || cookie.indexOf('\n') >= 0)
                throw new IllegalArgumentException("Invalid application cookie header");
        }
        response.setStatus(prepared.status);
        response.setContentType("application/json; charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("X-Content-Type-Options", "nosniff");
        if (prepared.retryAfterSeconds > 0)
            response.setHeader("Retry-After", Long.toString(prepared.retryAfterSeconds));
        for (String cookie : prepared.setCookieHeaders) response.addHeader("Set-Cookie", cookie);
        response.setContentLength(prepared.body.length);
        if (!request.getMethod().equals("HEAD")) response.getOutputStream().write(prepared.body);
    }

    private static final class Prepared {
        private final int status;
        private final byte @NonNull [] body;
        private final @NonNull List<@NonNull String> setCookieHeaders;
        private final long retryAfterSeconds;
        private Prepared(int status, byte @NonNull [] body, @NonNull List<@NonNull String> cookies,
                long retryAfterSeconds) {
            this.status = status;
            this.body = body;
            this.setCookieHeaders = cookies;
            this.retryAfterSeconds = retryAfterSeconds;
        }
        private @NonNull Prepared withCookies(@NonNull List<@NonNull String> cookies) {
            return new Prepared(this.status, this.body, List.copyOf(cookies), this.retryAfterSeconds);
        }
        private @NonNull Prepared withRetryAfter(long seconds) {
            return new Prepared(this.status, this.body, this.setCookieHeaders, seconds);
        }
    }

    /** Confirmed app transaction receipt. Each header includes Secure, HttpOnly and SameSite. */
    @Immutable
    public static final class LoginCompletion {
        private final @NonNull List<@NonNull String> setCookieHeaders;
        private LoginCompletion(@NonNull List<@NonNull String> headers) {
            this.setCookieHeaders = List.copyOf(headers);
        }
        public static @NonNull LoginCompletion fromSetCookieHeaders(@NonNull List<@NonNull String> headers) {
            return new LoginCompletion(headers);
        }
        public @NonNull List<@NonNull String> getSetCookieHeaders() { return this.setCookieHeaders; }
        @Override public @NonNull String toString() { return "LoginCompletion[redacted]"; }
    }

    /** Held on the caller thread until core proof and the application transaction finish. */
    @NotThreadSafe
    public interface RequestPermit extends AutoCloseable {
        @NonNull String getRecoveryEpoch();
        @NonNull Boolean isCurrent();
        @Override void close();
    }

    /**
     * App-owned admission and persistence. Admission rejects non-exact Host/Origin, missing or
     * duplicate cookie/CSRF/media headers, non-ASCII or oversized raw bodies, and duplicate input.
     * It resolves account IDs and bindings from server-owned state, never caller-supplied fields.
     * Both login admissions require a short-lived, primary-authenticated pending session. Their
     * completion atomically rechecks and consumes that pending state, pins the factor ID and epoch,
     * rotates session/CSRF and records the TOTP versus restricted recovery method. Management
     * admission consumes a fresh, purpose-bound approval or explicit approved recovery path.
     * All hooks honor the request budget; uncertain writes release no credentials or plaintext.
     */
    @ThreadSafe
    public interface ApplicationSecurity {
        @Nullable RequestPermit acquireRequestPermit(@NonNull HttpServletRequest request,
                @NonNull Duration budget) throws IOException;
        @Nullable EnrollmentContext admitEnrollment(@NonNull HttpServletRequest request,
                boolean replacement) throws IOException;
        @Nullable EnrollmentSubmission admitEnrollmentConfirmation(@NonNull HttpServletRequest request)
                throws IOException;
        @Nullable LoginSubmission admitTotpLogin(@NonNull HttpServletRequest request) throws IOException;
        @Nullable LoginSubmission admitRecoveryLogin(@NonNull HttpServletRequest request) throws IOException;
        @Nullable RotationContext admitRecoveryRotation(@NonNull HttpServletRequest request) throws IOException;
        @Nullable RemovalContext admitRemoval(@NonNull HttpServletRequest request) throws IOException;
        @Nullable CancellationContext admitCancellation(@NonNull HttpServletRequest request) throws IOException;
        @Nullable ActionContext admitStatus(@NonNull HttpServletRequest request) throws IOException;
        boolean rememberEnrollment(@NonNull EnrollmentContext context, @NonNull String enrollmentId,
                @NonNull String factorId, @NonNull Instant expiresAt);
        boolean completeEnrollment(@NonNull EnrollmentSubmission context, @NonNull TotpFactor factor,
                @NonNull String recoveryBatchId);
        @Nullable LoginCompletion completeTotpLogin(@NonNull LoginSubmission context,
                @NonNull TotpVerification proof);
        @Nullable LoginCompletion completeRecoveryLogin(@NonNull LoginSubmission context,
                @NonNull RecoveryCodeUse proof);
        boolean completeRotation(@NonNull RotationContext context, @NonNull String newBatchId);
        boolean completeRemoval(@NonNull RemovalContext context);
        boolean completeCancellation(@NonNull CancellationContext context);
        void requireReconciliation(@NonNull ActionContext context);
    }

    @ThreadSafe public interface ActionContext { @NonNull String getAccountId(); }
    @ThreadSafe public interface EnrollmentContext extends ActionContext {
        @NonNull String getAccountLabel();
        @NonNull String getBrowserBinding();
        @NonNull Optional<@NonNull String> getReplacingFactorId();
    }
    @ThreadSafe public interface EnrollmentSubmission extends ActionContext {
        @NonNull String getEnrollmentId();
        @NonNull String getCode();
        @NonNull String getBrowserBinding();
    }
    @ThreadSafe public interface LoginSubmission extends ActionContext {
        @NonNull String getCode();
        @NonNull String getOperationBinding();
    }
    @ThreadSafe public interface RotationContext extends ActionContext {
        @NonNull String getExpectedFactorId();
        @NonNull String getExpectedBatchId();
    }
    @ThreadSafe public interface RemovalContext extends ActionContext {
        @NonNull String getExpectedFactorId();
    }
    @ThreadSafe public interface CancellationContext extends ActionContext {
        @NonNull String getEnrollmentId();
        @NonNull String getBrowserBinding();
    }
}
