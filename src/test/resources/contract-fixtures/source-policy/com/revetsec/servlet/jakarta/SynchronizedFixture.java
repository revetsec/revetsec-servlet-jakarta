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

/**
 * Seeded violations: a synchronized method, a synchronized statement, and two statements that only javac sees as
 * synchronized because they are spelled with Unicode escapes. The word in this comment, the line comment and the
 * literals below are controls and must not be reported: synchronized.
 */
final class SynchronizedFixture {
	// synchronized in a line comment
	private static final String TEXT = "synchronized in a string";
	private static final String BLOCK = """
			synchronized in a text block
			""";
	private final Object lock = new Object();

	public synchronized void seeded() {
	}

	void statement() {
		synchronized (lock) {
			lock.hashCode();
		}
	}

	void escaped() {
		// javac ends this comment at the escaped line terminator, so the block is live code: \u000a synchronized (lock) { lock.hashCode(); }
		\u0073ynchronized (lock) {
			lock.hashCode();
		}
	}
}
