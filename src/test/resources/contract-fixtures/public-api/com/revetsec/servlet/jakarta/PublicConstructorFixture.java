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
 * Seeded violations: a public concrete type with public and protected constructors (R1).
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class PublicConstructorFixture {
	/**
	 * A public constructor, which R1 forbids.
	 *
	 * @since 1.0.0
	 */
	public PublicConstructorFixture() {
	}

	/**
	 * A protected constructor, which R1 forbids too.
	 *
	 * @param name a name
	 * @since 1.0.0
	 */
	protected PublicConstructorFixture(@NonNull String name) {
	}
}
