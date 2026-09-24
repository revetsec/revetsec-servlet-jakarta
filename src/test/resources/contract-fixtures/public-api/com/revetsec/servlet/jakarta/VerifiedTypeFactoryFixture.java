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

import com.revetsec.jose.Jwt;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.List;
import java.util.Optional;

/**
 * Seeded violations: public static methods that return a verified (R17) core type. The package-private method is
 * a control.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class VerifiedTypeFactoryFixture {
	private VerifiedTypeFactoryFixture() {
	}

	/**
	 * Seeded violation.
	 *
	 * @param authorizationHeader a header value
	 * @return never
	 * @since 1.0.0
	 */
	public static @NonNull Jwt jwtFor(@NonNull String authorizationHeader) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Seeded violation: the verified type is a type argument.
	 *
	 * @param authorizationHeader a header value
	 * @return never
	 * @since 1.0.0
	 */
	public static @NonNull Optional<@NonNull List<@NonNull Jwt>> jwtsFor(@NonNull String authorizationHeader) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Seeded violation: the verified type is a type-variable bound.
	 *
	 * @param <T> the token type
	 * @return never
	 * @since 1.0.0
	 */
	public static <T extends @NonNull Jwt> @NonNull T forge() {
		throw new UnsupportedOperationException();
	}

	static @NonNull Jwt packagePrivateJwtFor(@NonNull String authorizationHeader) {
		throw new UnsupportedOperationException();
	}
}
