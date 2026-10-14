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
import com.revetsec.scim.ScimError;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/** A bounded raw Servlet body read; availability is distinct from protocol rejection.
 * @since 1.0.0
 */
@Immutable
public sealed interface ServletScimBodyResult permits ServletScimBodyResult.Read,
        ServletScimBodyResult.Rejected, ServletScimBodyResult.Unavailable {
    /** An unchanged raw body that may contain personal data.
     * @since 1.0.0
     */
    @Immutable final class Read implements ServletScimBodyResult {
        private final byte @NonNull [] body;
        Read(byte @NonNull [] body) { this.body = requireNonNull(body).clone(); }
        /** Returns a defensive copy of the original body.
         * @return the original bytes, which may contain personal data
         * @since 1.0.0
         */
        @CheckReturnValue public byte @NonNull [] getBodyWithPersonalData() { return body.clone(); }
        @Override public @NonNull String toString() { return "ServletScimBodyResult.Read{<redacted>}"; }
    }
    /** An explicit body-size rejection with no retained request bytes.
     * @since 1.0.0
     */
    @Immutable final class Rejected implements ServletScimBodyResult {
        private final @NonNull ScimError error;
        Rejected(@NonNull ScimError error) { this.error = requireNonNull(error); }
        /** Returns the fixed protocol error.
         * @return the error
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimError getError() { return error; }
        @Override public @NonNull String toString() { return "ServletScimBodyResult.Rejected{<redacted>}"; }
    }
    /** The input stream was unavailable; the application chooses its transport failure handling.
     * @since 1.0.0
     */
    @Immutable final class Unavailable implements ServletScimBodyResult {
        static final @NonNull Unavailable INSTANCE = new Unavailable();
        private Unavailable() { }
        @Override public @NonNull String toString() { return "ServletScimBodyResult.Unavailable"; }
    }
}
