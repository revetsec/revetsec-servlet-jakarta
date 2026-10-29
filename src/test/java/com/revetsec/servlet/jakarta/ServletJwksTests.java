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
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.PublishedJwk;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

final class ServletJwksTests {

	@Test
	void getAndPreparedResponsesRetainCoreStatusHeadersAndExactBytes() throws Exception {
		JwksPublisher publisher = publisher();
		JwksResponse prepared = publisher.responseFor("GET");
		CapturedResponse direct = new CapturedResponse(null);
		ServletJwks.writeResponse(direct.response(), prepared);
		assertSameResponse(prepared, direct);
		CapturedResponse routed = new CapturedResponse(null);
		ServletJwks.writeResponse(publisher, request("GET", Collections.emptyEnumeration()), routed.response());
		assertSameResponse(prepared, routed);
		assertEquals(1, routed.outputStreamCalls);
	}

	@Test
	void headAndNotModifiedNeverObtainOutputStreamAndOtherMethodsUseCoreRejections() throws Exception {
		JwksPublisher publisher = publisher();
		CapturedResponse head = new CapturedResponse(new IOException("must not obtain output stream"));
		ServletJwks.writeResponse(publisher, request("HEAD", Collections.emptyEnumeration()), head.response());
		assertSameResponse(publisher.responseFor("HEAD"), head);
		assertEquals(publisher.responseFor("GET").getHeaders(), head.headers);
		assertEquals(0, head.outputStreamCalls);

		CapturedResponse unchanged = new CapturedResponse(new IOException("must not obtain output stream"));
		ServletJwks.writeResponse(publisher, request("GET", Collections.enumeration(List.of("*"))), unchanged.response());
		assertSameResponse(publisher.responseFor("GET", "*"), unchanged);
		assertEquals(304, unchanged.status);
		assertEquals(0, unchanged.outputStreamCalls);

		CapturedResponse rejected = new CapturedResponse(null);
		ServletJwks.writeResponse(publisher, request("POST", Collections.emptyEnumeration()), rejected.response());
		assertSameResponse(publisher.responseFor("POST"), rejected);
		assertEquals(405, rejected.status);
	}

	@Test
	void conditionalRequestCombinesEveryPhysicalOccurrence() throws Exception {
		JwksPublisher publisher = publisher();
		String etag = requireNonNull(publisher.responseFor("GET").getHeaders().get("ETag")).get(0);
		CapturedResponse conditional = new CapturedResponse(null);
		ServletJwks.writeResponse(publisher, request("GET", Collections.enumeration(List.of("\"old\"", "W/" + etag))),
				conditional.response());
		assertSameResponse(publisher.responseFor("GET", "\"old\",W/" + etag), conditional);
		assertEquals(304, conditional.status);
	}

	@Test
	void conditionalHeaderCombinationBoundsBothCharactersAndEnumeration() throws Exception {
		JwksPublisher publisher = publisher();
		for (List<String> values : List.of(List.of("private-input".repeat(1_000)),
				List.of("x".repeat(4_096), "y".repeat(4_096)))) {
			CapturedResponse rejected = new CapturedResponse(null);
			ServletJwks.writeResponse(publisher, request("GET", Collections.enumeration(values)), rejected.response());
			assertSameResponse(publisher.responseFor("GET", "x".repeat(8_193)), rejected);
			assertEquals(400, rejected.status);
			assertFalse(rejected.body.toString(java.nio.charset.StandardCharsets.UTF_8).contains("private-input"));
		}
		AtomicInteger read = new AtomicInteger();
		Enumeration<String> endless = new Enumeration<>() {
			@Override public boolean hasMoreElements() { return true; }
			@Override public @NonNull String nextElement() { read.incrementAndGet(); return ""; }
		};
		CapturedResponse rejected = new CapturedResponse(null);
		ServletJwks.writeResponse(publisher, request("GET", endless), rejected.response());
		assertEquals(400, rejected.status);
		assertEquals(8_194, read.get());
	}

	@Test
	void unavailableHeadersAndOutputFailuresRemainVisibleToApplication() throws Exception {
		JwksPublisher publisher = publisher();
		CapturedResponse unavailable = new CapturedResponse(null);
		assertThrows(IllegalStateException.class,
				() -> ServletJwks.writeResponse(publisher, request("GET", null), unavailable.response()));
		assertEquals(0, unavailable.status);
		assertTrue(unavailable.headers.isEmpty());

		IOException failure = new IOException("output failure");
		CapturedResponse failed = new CapturedResponse(failure);
		assertSame(failure, assertThrows(IOException.class,
				() -> ServletJwks.writeResponse(failed.response(), publisher.responseFor("GET"))));
	}

	@Test
	@SuppressWarnings("NullAway") // Exercises runtime checks for deliberately invalid Java callers.
	void requiredArgumentsRejectNull() throws Exception {
		JwksPublisher publisher = publisher();
		HttpServletRequest request = request("GET", Collections.emptyEnumeration());
		HttpServletResponse response = new CapturedResponse(null).response();
		assertThrows(NullPointerException.class, () -> ServletJwks.writeResponse(null, request, response));
		assertThrows(NullPointerException.class, () -> ServletJwks.writeResponse(publisher, null, response));
		assertThrows(NullPointerException.class, () -> ServletJwks.writeResponse(publisher, request, null));
		assertThrows(NullPointerException.class, () -> ServletJwks.writeResponse(null, publisher.responseFor("GET")));
		assertThrows(NullPointerException.class, () -> ServletJwks.writeResponse(response, null));
	}

	private static @NonNull JwksPublisher publisher() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2_048);
		return JwksPublisher.withKeys(List.of(PublishedJwk.withPublicKey(generator.generateKeyPair().getPublic())
				.keyId("epic-prod").algorithm(JwsAlgorithm.RS384).build())).httpCacheMaxAge(Duration.ofHours(1)).build();
	}

	private static @NonNull HttpServletRequest request(@NonNull String method,
			@Nullable Enumeration<@NonNull String> conditionalHeaders) {
		return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
				new Class<?>[]{HttpServletRequest.class}, (proxy, called, arguments) -> switch (called.getName()) {
					case "getMethod" -> method;
					case "getHeaders" -> {
						assertEquals("If-None-Match", requireNonNull(arguments)[0]);
						yield conditionalHeaders;
					}
					default -> throw new UnsupportedOperationException(called.getName());
				});
	}

	private static void assertSameResponse(@NonNull JwksResponse prepared, @NonNull CapturedResponse actual) {
		assertEquals(prepared.getStatusCode(), actual.status);
		assertEquals(prepared.getHeaders(), actual.headers);
		assertArrayEquals(prepared.toHttpBody(), actual.body.toByteArray());
	}

	private static final class CapturedResponse {
		private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers = new LinkedHashMap<>();
		private final @NonNull ByteArrayOutputStream body = new ByteArrayOutputStream();
		private final @Nullable IOException failure;
		private int status;
		private int outputStreamCalls;

		private CapturedResponse(@Nullable IOException failure) { this.failure = failure; }

		private @NonNull HttpServletResponse response() {
			ServletOutputStream output = new ServletOutputStream() {
				@Override public void write(int value) { body.write(value); }
				@Override public boolean isReady() { return true; }
				@Override public void setWriteListener(@NonNull WriteListener listener) { throw new UnsupportedOperationException(); }
			};
			return (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
					new Class<?>[]{HttpServletResponse.class}, (proxy, called, arguments) -> {
						switch (called.getName()) {
							case "setStatus" -> status = (Integer) requireNonNull(arguments)[0];
							case "setHeader" -> headers.put((String) requireNonNull(arguments)[0],
									new ArrayList<>(List.of((String) arguments[1])));
							case "addHeader" -> headers.computeIfAbsent((String) requireNonNull(arguments)[0],
									ignored -> new ArrayList<>()).add((String) arguments[1]);
							case "getOutputStream" -> {
								outputStreamCalls++;
								if (failure != null) throw failure;
								return output;
							}
							default -> throw new UnsupportedOperationException(called.getName());
						}
						return null;
					});
		}
	}
}
