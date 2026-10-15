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

import com.revetsec.jose.JwksPublisher;
import com.revetsec.jose.JwksResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Publishes standalone public JSON Web Key Sets on application-owned Servlet routes.
 * The core publisher prepares method handling, conditional responses, cache headers and JSON bytes.
 * Applications choose the route and its key set; no OAuth authorization server is required.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class ServletJwks {

	private static final int MAXIMUM_CONDITIONAL_HEADER_CHARACTERS = 8_192;

	private ServletJwks() {}

	/**
	 * Prepares and writes a standalone JWKS response using every {@code If-None-Match} occurrence.
	 * Servlet header lookup is case-insensitive and retains repeated physical field values.
	 *
	 * @param publisher configured public-key publisher
	 * @param request request on the application's JWKS route
	 * @param response application-owned transport response
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalStateException if the Servlet does not expose request headers
	 * @throws IOException if the Servlet output stream fails
	 * @since 1.0.0
	 */
	public static void writeResponse(@NonNull JwksPublisher publisher,
			@NonNull HttpServletRequest request, @NonNull HttpServletResponse response) throws IOException {
		requireNonNull(publisher);
		requireNonNull(request);
		requireNonNull(response);
		writeResponse(response, publisher.responseFor(request.getMethod(), ifNoneMatchFor(request)));
	}

	/**
	 * Writes a prepared core response without JSON marshalling or header regeneration.
	 * A prepared HEAD or not-modified response does not obtain or write the output stream.
	 *
	 * @param response application-owned transport response
	 * @param prepared prepared standalone JWKS response
	 * @throws NullPointerException if a required argument is null
	 * @throws IOException if the Servlet output stream fails
	 * @since 1.0.0
	 */
	public static void writeResponse(@NonNull HttpServletResponse response,
			@NonNull JwksResponse prepared) throws IOException {
		requireNonNull(response);
		requireNonNull(prepared);
		response.setStatus(prepared.getStatusCode());
		for (Map.Entry<String, List<String>> header : prepared.getHeaders().entrySet()) {
			boolean first = true;
			for (String value : header.getValue()) {
				if (first)
					response.setHeader(header.getKey(), value);
				else
					response.addHeader(header.getKey(), value);
				first = false;
			}
		}
		byte[] body = prepared.toHttpBody();
		if (body.length != 0)
			response.getOutputStream().write(body);
	}

	private static @Nullable String ifNoneMatchFor(@NonNull HttpServletRequest request) {
		Enumeration<String> values = request.getHeaders("If-None-Match");
		if (values == null)
			throw new IllegalStateException("Servlet request headers are unavailable");
		StringBuilder combined = new StringBuilder();
		boolean present = false;
		while (values.hasMoreElements()) {
			String value = requireNonNull(values.nextElement());
			int separator = present ? 1 : 0;
			if (value.length() > MAXIMUM_CONDITIONAL_HEADER_CHARACTERS - combined.length() - separator)
				return "x".repeat(MAXIMUM_CONDITIONAL_HEADER_CHARACTERS + 1);
			if (present)
				combined.append(',');
			combined.append(value);
			present = true;
		}
		return present ? combined.toString() : null;
	}
}
