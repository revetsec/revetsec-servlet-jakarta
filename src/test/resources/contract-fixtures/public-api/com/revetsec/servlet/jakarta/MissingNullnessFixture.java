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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.util.List;
import java.util.Optional;

/**
 * Seeded violations: public signatures without JSpecify nullness, and forbidden factory names.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class MissingNullnessFixture {
	private MissingNullnessFixture() {
	}

	/**
	 * Seeded violation: a factory named of().
	 *
	 * @return an instance
	 * @since 1.0.0
	 */
	public static @NonNull MissingNullnessFixture of() {
		return new MissingNullnessFixture();
	}

	/**
	 * Seeded violation: a factory named createDefault().
	 *
	 * @return an instance
	 * @since 1.0.0
	 */
	public static @NonNull MissingNullnessFixture createDefault() {
		return new MissingNullnessFixture();
	}

	/**
	 * Unannotated parameter and return type.
	 *
	 * @param input input
	 * @return output
	 * @since 1.0.0
	 */
	public String unannotated(String input) {
		return input;
	}

	/**
	 * Unannotated type argument.
	 *
	 * @return names
	 * @since 1.0.0
	 */
	public @NonNull List<String> unannotatedTypeArgument() {
		return List.of();
	}

	/**
	 * Optional's type argument must be non-null.
	 *
	 * @return maybe
	 * @since 1.0.0
	 */
	public @NonNull Optional<@Nullable String> nullableOptionalValue() {
		return Optional.empty();
	}
}
