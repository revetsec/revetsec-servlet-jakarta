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
package com.revetsec.servlet.jakarta;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Outcome of a bounded raw WebAuthn completion-body read. The application handles every branch
 * before passing the bytes to core with its application-held ceremony ID and browser binding.
 * @since 1.0.0
 */
@Immutable
public sealed interface ServletWebAuthnBodyResult permits ServletWebAuthnBodyResult.Read,
        ServletWebAuthnBodyResult.Rejected, ServletWebAuthnBodyResult.Unavailable {
    /** The original raw JSON body, which may contain personal data.
     * @since 1.0.0
     */
    @Immutable final class Read implements ServletWebAuthnBodyResult {
        private final byte @NonNull [] body;
        Read(byte @NonNull [] body) { this.body = requireNonNull(body).clone(); }

        /** Returns a defensive copy of the original body.
         * @return unchanged bytes, which may contain personal data
         * @since 1.0.0
         */
        @CheckReturnValue public byte @NonNull [] getBodyWithPersonalData() { return this.body.clone(); }
        @Override public @NonNull String toString() { return "ServletWebAuthnBodyResult.Read{<redacted>}"; }
    }

    /** Method, media type or body size was rejected without retaining body bytes.
     * @since 1.0.0
     */
    @Immutable final class Rejected implements ServletWebAuthnBodyResult {
        static final @NonNull Rejected INSTANCE = new Rejected();
        private Rejected() { }
        @Override public @NonNull String toString() { return "ServletWebAuthnBodyResult.Rejected"; }
    }

    /** Input could not be read; the application chooses transport failure handling.
     * @since 1.0.0
     */
    @Immutable final class Unavailable implements ServletWebAuthnBodyResult {
        static final @NonNull Unavailable INSTANCE = new Unavailable();
        private Unavailable() { }
        @Override public @NonNull String toString() { return "ServletWebAuthnBodyResult.Unavailable"; }
    }
}
