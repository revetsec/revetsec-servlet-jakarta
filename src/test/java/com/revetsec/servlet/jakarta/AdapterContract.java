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

import java.util.List;

/**
 * The facts that differ between Revetsec's adapter repositories.
 * <p>
 * The other contract-test sources are the same in {@code revetsec-soklet}, {@code revetsec-servlet-jakarta} and
 * {@code revetsec-servlet-javax} apart from their package declaration, so a change to one can be copied to the
 * others unchanged.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class AdapterContract {
	/**
	 * The adapter's single package. Every main source belongs to it, and it is the only exported package.
	 */
	static final String ADAPTER_PACKAGE = "com.revetsec.servlet.jakarta";

	/**
	 * The first line of {@code NOTICE} and of the JAR's {@code META-INF/NOTICE}; also the POM {@code <name>}.
	 */
	static final String PRODUCT_NAME = "Revetsec Servlet Adapter (jakarta)";

	/**
	 * Binary names of classes whose JARs the contract tests put on javac's class path, next to the annotation JARs,
	 * so adapter sources can be attributed: Revetsec core and the framework API. Core is located through its root
	 * {@code package-info}, which exists at every milestone.
	 */
	static final List<String> DEPENDENCY_ANCHOR_CLASSES = List.of(
			"com.revetsec.package-info",
			"jakarta.servlet.http.HttpServletRequest");

	private AdapterContract() {
		// Non-instantiable
	}

	/**
	 * The adapter package as a relative source path, such as {@code com/revetsec/servlet/jakarta}.
	 */
	static String adapterPackagePath() {
		return ADAPTER_PACKAGE.replace('.', '/');
	}
}
