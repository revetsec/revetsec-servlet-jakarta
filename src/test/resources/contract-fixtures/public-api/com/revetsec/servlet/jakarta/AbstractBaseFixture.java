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

/**
 * Seeded violations reached through inheritance: this package-private base class is not exported, but its public
 * members are callable through the exported {@link InheritingFixture}.
 */
abstract class AbstractBaseFixture {
	AbstractBaseFixture() {
	}

	/**
	 * Documented and annotated; the problem is that it returns a verified type.
	 *
	 * @param authorizationHeader a header value
	 * @return never
	 * @since 1.0.0
	 */
	public static @NonNull Jwt parse(@NonNull String authorizationHeader) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Documented and annotated; the problem is the factory name.
	 *
	 * @return never
	 * @since 1.0.0
	 */
	public static @NonNull String newToken() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Documented, but without a since tag.
	 *
	 * @return a value
	 */
	public @NonNull String undated() {
		return "";
	}

	public String undocumented(String value) {
		return value;
	}
}
