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
import java.util.Map;
import java.util.Optional;

/**
 * Control: satisfies every public API contract, so no violation may mention it.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class CompliantFixture {
	/**
	 * A constant.
	 *
	 * @since 1.0.0
	 */
	public static final @NonNull String NAME = "compliant";

	private CompliantFixture() {
	}

	/**
	 * Returns values.
	 *
	 * @param input the input
	 * @param count a primitive, which needs no nullness annotation
	 * @return the values
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull String> values(@Nullable Map<@NonNull String, @Nullable String> input, int count) {
		return List.of();
	}

	/**
	 * Finds a value.
	 *
	 * @param names names
	 * @return the value, if any
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> find(@NonNull String @Nullable [] names) {
		return Optional.empty();
	}

	/**
	 * A factory named per the naming conventions.
	 *
	 * @return an instance
	 * @since 1.0.0
	 */
	public static @NonNull CompliantFixture fromDefaults() {
		return new CompliantFixture();
	}

	/**
	 * Not a factory name: "offset" only starts with the letters o and f.
	 *
	 * @return zero
	 * @since 1.0.0
	 */
	public static @NonNull Integer offset() {
		return 0;
	}

	@Override
	public @NonNull String toString() {
		return NAME;
	}

	/**
	 * A nested enum.
	 *
	 * @since 1.0.0
	 */
	@ThreadSafe
	public enum Mode {
		/**
		 * The first mode.
		 */
		FIRST
	}
}
