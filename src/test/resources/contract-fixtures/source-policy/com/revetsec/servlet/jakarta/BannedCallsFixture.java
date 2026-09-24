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
 * Seeded violations for SourcePolicyTests. Each statement in a seeded method carries one banned construct, and every
 * detection alternative has at least one line that only it reports (ContractMetaTests checks both). Types are fully
 * qualified so that no import line reports anything; InsecureRandomFixture seeds the simple names and XmlFixture
 * the XML rules. In an adapter even core's exemptions (the default HttpClient holder) are banned. Nothing in
 * controls() may be reported.
 */
final class BannedCallsFixture {
	void backgroundWork(Runnable runnable, Thread thread, java.util.List<String> values,
			java.util.stream.Stream<String> stream, java.util.concurrent.CompletableFuture<String> future,
			java.util.concurrent.CompletionStage<String> stage, java.util.concurrent.ForkJoinTask<String> task) {
		new Thread(runnable);
		new java.lang.Thread(runnable);
		java.util.function.Function<Runnable, Thread> threads = Thread::new;
		new WorkerThread();
		thread.start();
		new java.util.Timer();
		new java.util.TimerTask() {
			@Override
			public void run() {
			}
		};
		new java.util.concurrent.ForkJoinPool();
		java.util.concurrent.Executors.newCachedThreadPool();
		java.util.function.Supplier<java.util.concurrent.ExecutorService> executors =
				java.util.concurrent.Executors::newCachedThreadPool;
		java.util.concurrent.Executors
				.newSingleThreadExecutor();
		java.util.concurrent.ForkJoinPool.commonPool();
		task.fork();
		java.util.concurrent.CompletableFuture.runAsync(runnable);
		java.util.concurrent.CompletableFuture
				.supplyAsync(() -> "value");
		future.thenAcceptBothAsync(future, (first, second) -> { });
		future.applyToEitherAsync(future, value -> value);
		stage.thenApplyAsync(value -> value);
		future.orTimeout(1, java.util.concurrent.TimeUnit.SECONDS);
		future.completeOnTimeout("value", 1, java.util.concurrent.TimeUnit.SECONDS);
		java.util.concurrent.CompletableFuture.delayedExecutor(1, java.util.concurrent.TimeUnit.SECONDS);
		future.defaultExecutor();
		java.lang.ref.Cleaner.create();
		values.parallelStream();
		stream.parallel();
		java.util.Arrays.parallelSort(new int[0]);
		java.util.concurrent.ScheduledExecutorService scheduled = null;
	}

	void otherBans(Throwable failure, String text, java.util.List<Throwable> failures, java.util.List<String> values,
			java.lang.reflect.Field field) throws Exception {
		failure.printStackTrace();
		failures.forEach(Throwable::printStackTrace);
		Thread.dumpStack();
		text.toLowerCase();
		text.toUpperCase();
		values.stream().map(String::toLowerCase);
		"Title"
				.toUpperCase();
		new java.net.URI("https", "example.com", "/path", "query=" + "value", null);
		java.net.http.HttpClient.newHttpClient();
		java.net.http.HttpClient
				.newBuilder();
		new java.io.ObjectInputStream(null);
		new java.beans.XMLDecoder((java.io.InputStream) null);
		field.setAccessible(true);
		field.trySetAccessible();
		java.lang.invoke.MethodHandles.privateLookupIn(String.class, java.lang.invoke.MethodHandles.lookup());
		sun.misc.Unsafe.class.getName();
		java.util.Base64.getMimeDecoder();
		java.util.ServiceLoader.load(Runnable.class);
		System.out.println("console");
		System.err.println("console");
		System
				.out.println("console");
		new java.util.Random();
		new java.util.SplittableRandom();
		java.util.concurrent.ThreadLocalRandom.current();
		java.util.random.RandomGenerator.of("L64X128MixRandom");
		Math.random();
		StrictMath.random();
		java.util.function.DoubleSupplier doubles = Math::random;
	}

	void jvmGlobals(java.net.URLConnection plain, javax.net.ssl.HttpsURLConnection connection,
			java.net.HttpURLConnection conn) throws Exception {
		System.setProperty("jdk.xml.entityExpansionLimit", "0");
		System.clearProperty("jdk.xml.entityExpansionLimit");
		System.setProperties(null);
		System.setSecurityManager(null);
		System.setOut(null);
		System.setErr(null);
		System.setIn(null);
		java.security.Security.setProperty("securerandom.source", "file:/dev/urandom");
		java.security.Security.addProvider(null);
		java.security.Security.insertProviderAt(null, 1);
		java.security.Security.removeProvider("SUN");
		java.util.Locale.setDefault(java.util.Locale.ROOT);
		java.util.TimeZone.setDefault(null);
		javax.net.ssl.SSLContext.setDefault(null);
		java.net.Authenticator.setDefault(null);
		java.net.CookieHandler.setDefault(null);
		java.net.ProxySelector.setDefault(null);
		java.net.ResponseCache.setDefault(null);
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
		javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(null);
		java.net.URLConnection.setDefaultUseCaches("https", false);
		java.net.HttpURLConnection.setFollowRedirects(false);
		java.net.URL.setURLStreamHandlerFactory(null);
		java.net.URLConnection.setContentHandlerFactory(null);
		java.net.URLConnection.setFileNameMap(null);
		java.net.Socket.setSocketImplFactory(null);
		Thread.setDefaultUncaughtExceptionHandler(null);
		java.security.Policy.setPolicy(null);
		connection.setDefaultHostnameVerifier((host, session) -> true);
		connection.setDefaultSSLSocketFactory(null);
		plain.setDefaultUseCaches(false);
		conn.setFollowRedirects(false);
		java.util.Locale.ROOT.setDefault(java.util.Locale.ROOT);
		java.util.function.BiFunction<String, String, String> properties = System::setProperty;
		System.getProperties().setProperty("jdk.xml.entityExpansionLimit", "0");
	}

	/// Seeded violation: a Markdown doc comment, which javac 23 and later read as documentation and 17 and 21 ignore.
	void markdownDocComments() {
		int value = 0; //// javac 23 and later read a trailing comment with more slashes as one too
	}

	void unicodeEscapes() {
		// javac ends this comment at the escaped line terminator, so the call is live code: \u000a java.util.ServiceLoader.load(Runnable.class);
		\u0053ystem.err.println("escaped");
		\u002f\u002f\u002f a Markdown doc comment spelled with escapes
	}

	void controls(String text, java.util.List<String> values, Runnable runnable) throws Exception {
		text.toLowerCase(java.util.Locale.ROOT);
		values.stream().map(value -> value.toUpperCase(java.util.Locale.ROOT));
		values.stream().map(String::strip);
		new java.net.URI("https://example.com/path?" + String.join("&", "a=1", "b=2"));
		new java.security.SecureRandom().nextInt();
		java.util.concurrent.Executor callerRuns = Runnable::run;
		callerRuns.execute(runnable);
		String prose = "System.out, synchronized, java.util.Random and Executors in a string are not code";
		boolean noncharacter = text.equals("\uFFFF") || text.equals("System.out after a U+FFFF literal is not code");
		String slashes = "/// in a string is not a comment"; // two slashes are an ordinary comment
		/* /// inside a block comment is not a line comment */
	}

	static final class WorkerThread extends Thread {
	}

	static final class Chore extends java.util.TimerTask {
		@Override
		public void run() {
		}
	}

	static final class InlineExecutor implements java.util.concurrent.Executor {
		@Override
		public void execute(Runnable command) {
			command.run();
		}
	}
}
