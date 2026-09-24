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

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exported type whose public members all come from a package-private base class; the violations are
 * {@link AbstractBaseFixture}'s.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class InheritingFixture extends AbstractBaseFixture {
	private InheritingFixture() {
	}
}
