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

import javax.annotation.concurrent.ThreadSafe;

/**
 * Holds two nested classes that ContractMetaTests lists in R1_EXCEPTIONS, one by its binary name and one by its
 * canonical name, which exempts nothing.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class ListedErrorsFixture {
	private ListedErrorsFixture() {
	}

	/**
	 * Listed, so it may be neither final nor sealed. Seeded violation: the listing does not allow its public
	 * constructor.
	 *
	 * @since 1.0.0
	 */
	@ThreadSafe
	public static class LegacyError {
		/**
		 * A public constructor, which R1 forbids even for a listed class.
		 *
		 * @param detail a detail
		 * @since 1.0.0
		 */
		public LegacyError(@NonNull String detail) {
		}
	}

	/**
	 * Seeded violation: listed only by its canonical name (Outer.Nested), so it must still be final or sealed.
	 *
	 * @since 1.0.0
	 */
	@ThreadSafe
	public static class RetiredError {
		private RetiredError() {
		}
	}
}
