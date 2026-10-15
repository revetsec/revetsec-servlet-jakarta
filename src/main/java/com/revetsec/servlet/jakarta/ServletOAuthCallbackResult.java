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

import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.AuthorizationResponseParseResult;
import com.revetsec.oauth.OAuthException;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * The outcome of materializing and parsing a raw, unverified OAuth browser callback. A successful parse grants no identity;
 * the configured OAuth or OpenID Connect client must complete the browser-bound transaction.
 * <p>
 * Only the producing operation constructs these outcomes. Value accessors exist only on the variant that
 * owns a value, and diagnostic text contains no callback data. Later releases may add variants;
 * consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class ServletOAuthCallbackResult
		permits ServletOAuthCallbackResult.Succeeded, ServletOAuthCallbackResult.Rejected, ServletOAuthCallbackResult.TooLarge {
	ServletOAuthCallbackResult() { }

	static @NonNull ServletOAuthCallbackResult fromResponse(@NonNull AuthorizationResponse response) {
		return new Succeeded(requireNonNull(response));
	}

	static @NonNull ServletOAuthCallbackResult fromRejected() {
		return new Rejected();
	}

	static @NonNull ServletOAuthCallbackResult fromTooLarge() {
		return new TooLarge();
	}

	static @NonNull ServletOAuthCallbackResult fromParseResult(@NonNull AuthorizationResponseParseResult result) {
		if (requireNonNull(result) instanceof AuthorizationResponseParseResult.Succeeded success)
			return fromResponse(success.getResponse());
		return fromRejected();
	}

	/**
	 * Returns the outcome kind without callback data.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "ServletOAuthCallbackResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * A syntactically parsed callback that remains unverified until transaction completion.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends ServletOAuthCallbackResult {
		private final @NonNull AuthorizationResponse response;
		private Succeeded(@NonNull AuthorizationResponse response) { this.response = response; }

		/**
		 * Returns the raw, unverified callback. It grants no identity or permission.
		 * @return the parsed callback
		 * @since 1.0.0
		 */
		public @NonNull AuthorizationResponse getResponse() { return this.response; }
	}

	/**
	 * A malformed, duplicate, oversized or split-channel callback.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends ServletOAuthCallbackResult {
		private Rejected() { }

		/**
		 * Returns a fixed reason without attacker-controlled callback data.
		 * @return malformed callback reason
		 * @since 1.0.0
		 */
		public OAuthException.@NonNull Reason getReason() { return OAuthException.Reason.CALLBACK_MALFORMED; }
	}
	/**
	 * The transport discarded an oversized request body or its bounded read observed overflow.
	 * No callback is available and no pending authorization state may be consumed.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class TooLarge extends ServletOAuthCallbackResult {
		private TooLarge() { }
	}

}
