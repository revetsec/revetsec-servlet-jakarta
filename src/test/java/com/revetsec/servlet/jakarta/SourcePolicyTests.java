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

import com.revetsec.servlet.jakarta.ContractSupport.SourceAnalysis;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.SynchronizedTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.NestingKind;
import javax.lang.model.element.TypeElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Source-level policy guards for properties functional tests cannot see, adapted from RevetSec core's (plan 12.3
 * M0, R4, R18, 14.6; Pyranid precedent). Two mechanisms check {@code src/main/java}:
 * <ul>
 *   <li>regular expressions, each rule a list of alternatives, matched over each whole file after Unicode escapes
 *   are translated and comments and string literals removed, so only live code counts and a construct split
 *   across lines still matches;</li>
 *   <li>javac-attributed checks for what text cannot see reliably: {@code synchronized} however it is spelled,
 *   banned methods and constructors reached through calls, method references, {@code new} or {@code super(...)},
 *   however the call is qualified (see {@link #MEMBER_BANS}), and classes that extend or implement a banned
 *   supertype ({@link #SUPERTYPE_BANS}).</li>
 * </ul>
 * Markdown documentation comments ({@code ///}, JEP 467) are banned too, because whether javac sees them depends on
 * the JDK that runs the contract tests, not on the source.
 * Every file must also sit in the directory of its declared package. Core's rules apply to the whole adapter,
 * without core's exemptions: an adapter creates no {@code HttpClient} (core's single holder does), and it never
 * parses or queries XML (only core's hardened {@code internal.xml} does), so the XML factory types may not even be
 * named.
 * <p>
 * The banned hostname of the compromised public SAML test IdP (plan 14.4) is checked across every file in the
 * repository, binary files and base64 certificate blocks included, the license header across every Java source and
 * script, and the JAR's legal files against the repository's.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SourcePolicyTests {
	/**
	 * The hostname is assembled from parts so this file never contains it.
	 */
	private static final Pattern BANNED_HOSTNAME = Pattern.compile("saml" + "test" + "\\." + "id",
			Pattern.CASE_INSENSITIVE);

	/**
	 * Base64 blocks that may hide the hostname in a text file: PEM bodies and XML signature certificates.
	 */
	private static final Pattern BASE64_BLOCK = Pattern.compile(
			"-----BEGIN [A-Z0-9 ]+-----([A-Za-z0-9+/=\\s]+)-----END "
					+ "|<(?:[\\w.-]+:)?X509Certificate>([A-Za-z0-9+/=\\s]+)<");

	/**
	 * The license header in {@code #}-comment form, for Python and shell scripts (M0 plan, "File header").
	 */
	static final String SCRIPT_LICENSE_HEADER = ContractSupport.LICENSE_HEADER.lines()
			.filter(line -> !line.equals("/*") && !line.equals(" */"))
			.map(line -> line.equals(" *") ? "#" : "#" + line.substring(2))
			.reduce("", (header, line) -> header + line + "\n");

	static final String SYNCHRONIZED = "synchronized";
	static final String BACKGROUND_WORK = "background-work";
	static final String DEFAULT_HTTP_CLIENT = "default-http-client";
	static final String PRINT_STACK_TRACE = "print-stack-trace";
	static final String LOCALE_LESS_CASE_CONVERSION = "locale-less-case-conversion";
	static final String JVM_GLOBAL_MUTATION = "jvm-global-mutation";
	static final String MULTI_ARGUMENT_URI = "multi-argument-uri";
	static final String PACKAGE_PATH_MISMATCH = "package-path-mismatch";
	static final String MARKDOWN_DOC_COMMENT = "markdown-doc-comment";

	/**
	 * Alternative IDs of the checks that are neither a regular expression nor a table entry.
	 */
	static final String SYNCHRONIZED_METHOD_ALTERNATIVE = SYNCHRONIZED + " method modifier";
	static final String SYNCHRONIZED_STATEMENT_ALTERNATIVE = SYNCHRONIZED + " statement";
	static final String PACKAGE_PATH_MISMATCH_ALTERNATIVE = PACKAGE_PATH_MISMATCH + " declared package";
	static final String MARKDOWN_DOC_COMMENT_ALTERNATIVE = MARKDOWN_DOC_COMMENT + " /// line comment";

	/**
	 * One banned construct: an ID used in messages, the regular-expression alternatives that detect it textually
	 * (a rule detected only by javac-attributed checks has none), and why it is banned. Every rule applies to every
	 * adapter source.
	 */
	static final class Rule {
		private final String id;
		private final List<String> alternatives;
		private final List<Pattern> patterns;
		private final String reason;

		Rule(String id, List<String> alternatives, String reason) {
			this.id = id;
			this.alternatives = List.copyOf(alternatives);
			this.patterns = alternatives.stream().map(regex -> Pattern.compile(regex, Pattern.MULTILINE)).toList();
			this.reason = reason;
		}

		String getId() {
			return this.id;
		}

		String alternativeId(int index) {
			return this.id + " /" + this.alternatives.get(index) + "/";
		}
	}

	/**
	 * A banned method or constructor, matched on javac-resolved method calls, method references, instance creations
	 * (anonymous classes included) and explicit {@code super(...)} or {@code this(...)} calls: a member whose name
	 * matches {@code names} ({@code <init>} for constructors), declared in {@code owner} or any subtype of it, with a
	 * parameter count from {@code minimumParameters} to {@code maximumParameters}.
	 */
	static final class MemberBan {
		private final String ruleId;
		private final String owner;
		private final Pattern names;
		private final int minimumParameters;
		private final int maximumParameters;

		MemberBan(String ruleId, String owner, String names) {
			this(ruleId, owner, names, 0, Integer.MAX_VALUE);
		}

		MemberBan(String ruleId, String owner, String names, int minimumParameters, int maximumParameters) {
			this.ruleId = ruleId;
			this.owner = owner;
			this.names = Pattern.compile(names);
			this.minimumParameters = minimumParameters;
			this.maximumParameters = maximumParameters;
		}

		String alternativeId() {
			return this.ruleId + " " + this.owner + "#/" + this.names.pattern() + "/ with " + this.minimumParameters
					+ (this.maximumParameters == Integer.MAX_VALUE ? " or more" : " to " + this.maximumParameters)
					+ " parameters";
		}
	}

	/**
	 * A banned supertype: no named class may extend or implement {@code owner}, directly or indirectly.
	 */
	static final class SupertypeBan {
		private final String ruleId;
		private final String owner;

		SupertypeBan(String ruleId, String owner) {
			this.ruleId = ruleId;
			this.owner = owner;
		}

		String alternativeId() {
			return this.ruleId + " class extending or implementing " + this.owner;
		}
	}

	/**
	 * One finding: the rule, the file (relative to the source root) and line, and which alternative found it.
	 */
	static final class Detection {
		private final String ruleId;
		private final String path;
		private final int line;
		private final String alternativeId;

		Detection(String ruleId, String path, int line, String alternativeId) {
			this.ruleId = ruleId;
			this.path = path;
			this.line = line;
			this.alternativeId = alternativeId;
		}

		/**
		 * {@code <rule> <path>:<line>}, the prefix of the violation message.
		 */
		String getKey() {
			return this.ruleId + " " + this.path + ":" + this.line;
		}

		String getAlternativeId() {
			return this.alternativeId;
		}
	}

	static final List<Rule> MAIN_SOURCE_RULES = List.of(
			new Rule(SYNCHRONIZED, List.of(), "use ReentrantLock; monitors pin virtual threads on JDK 17 and 21 (R4)"),
			new Rule(BACKGROUND_WORK, List.of("\\bScheduledExecutorService\\b"),
					"adapters create no threads, executors, timers or cleaners and use no shared pool (R4)"),
			new Rule(DEFAULT_HTTP_CLIENT, List.of("\\bHttpClient\\s*(?:\\.|::)\\s*(?:newHttpClient|newBuilder)\\b"),
					"adapters create no HttpClient; RevetSec core's single default client serves them (D36)"),
			new Rule("insecure-random", List.of(
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*Random\\b",
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*SplittableRandom\\b",
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*concurrent\\s*\\.\\s*ThreadLocalRandom\\b",
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*random\\b",
					"(?<![\\w.$])Random\\b",
					"(?<![\\w.$])SplittableRandom\\b",
					"(?<![\\w.$])ThreadLocalRandom\\b",
					"(?<![\\w.$])RandomGenerator\\b",
					"(?<![\\w.$])RandomGeneratorFactory\\b",
					"\\bMath\\s*(?:\\.|::)\\s*random\\b",
					"\\bStrictMath\\s*(?:\\.|::)\\s*random\\b"),
					"randomness comes from RevetSec core's SecureRandom entropy seam (R6)"),
			new Rule("console-output", List.of("\\bSystem\\s*\\.\\s*out\\b", "\\bSystem\\s*\\.\\s*err\\b"),
					"adapters never write to System.out or System.err (R16)"),
			new Rule(PRINT_STACK_TRACE, List.of(), "stack traces may carry secrets and must not be printed (R9, R16)"),
			new Rule(LOCALE_LESS_CASE_CONVERSION, List.of(), "pass Locale.ROOT (R18)"),
			new Rule("xml-factory", List.of(
					"\\bDocumentBuilderFactory\\b",
					"\\bSAXParserFactory\\b",
					"\\bTransformerFactory\\b",
					"\\bSchemaFactory\\b",
					"\\bXMLInputFactory\\b",
					"\\bXPathFactory\\b",
					"\\bXMLReaderFactory\\b"),
					"adapters never parse or transform XML; only RevetSec core's hardened internal.xml does"),
			new Rule("xpath", List.of("\\bXPath\\w*", "\\bjavax\\s*\\.\\s*xml\\s*\\.\\s*xpath\\b"),
					"SAML processing walks the verified DOM by namespace in core and never uses XPath (14.6)"),
			new Rule("non-namespace-dom-lookup", List.of("\\bgetElementsByTagName\\b"),
					"use getElementsByTagNameNS; unqualified lookups enable wrapping attacks (14.6)"),
			new Rule("java-deserialization", List.of("\\bObjectInputStream\\b", "\\bXMLDecoder\\b"),
					"Java object deserialization is never used"),
			new Rule("set-accessible",
					List.of("\\bsetAccessible\\b", "\\btrySetAccessible\\b", "\\bprivateLookupIn\\b"),
					"no reflection into private members (R19)"),
			new Rule("sun-internal-api", List.of("(?<![\\w.$])sun\\s*\\.\\s*(?:misc|reflect|security|nio|net|util"
							+ "|io|invoke|awt|font|java2d|rmi|management|tools|jvmstat|text|launcher|print|swing"
							+ "|instrument)\\b"),
					"sun.* is JDK-internal"),
			new Rule("mime-base64-decoder", List.of("\\bgetMimeDecoder\\b"),
					"the MIME decoder silently skips illegal characters (14.6)"),
			new Rule("service-loader", List.of("\\bServiceLoader\\b"), "no ServiceLoader (R4)"),
			// The setters are javac-resolved MEMBER_BANS, so a static setter called through an instance or an
			// expression (connection.setDefaultSSLSocketFactory, Locale.ROOT.setDefault) is caught too. The live
			// Properties object that System.getProperties() returns is the one thing text must catch.
			new Rule(JVM_GLOBAL_MUTATION, List.of("\\bSystem\\s*(?:\\.|::)\\s*getProperties\\b"),
					"adapters never mutate JVM-global settings (R4)"),
			new Rule(MULTI_ARGUMENT_URI, List.of(),
					"multi-argument URI constructors re-encode components and let parameters inject; leave URI "
							+ "building to RevetSec core, or use a single-argument constructor (14.6)"),
			new Rule(PACKAGE_PATH_MISMATCH, List.of(), "a file must sit in the directory of its declared package"),
			new Rule(MARKDOWN_DOC_COMMENT, List.of(),
					"use /** */ Javadoc; JDK 17/21 tooling ignores /// Markdown doc comments, so R20 and @since would "
							+ "pass or fail depending on the JDK (JEP 467)"));

	/**
	 * Banned methods and constructors, checked on javac-resolved references (see {@link MemberBan}).
	 */
	static final List<MemberBan> MEMBER_BANS = List.of(
			new MemberBan(BACKGROUND_WORK, "java.lang.Thread", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.lang.Thread", "start"),
			new MemberBan(BACKGROUND_WORK, "java.util.Timer", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.util.TimerTask", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.Executor", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.Executors", ".*"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.ForkJoinPool", "commonPool"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.ForkJoinTask", "fork|invokeAll"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.CompletionStage", "\\w+Async"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.CompletableFuture",
					"orTimeout|completeOnTimeout|delayedExecutor|defaultExecutor"),
			new MemberBan(BACKGROUND_WORK, "java.lang.ref.Cleaner", "create"),
			new MemberBan(BACKGROUND_WORK, "java.util.Collection", "parallelStream"),
			new MemberBan(BACKGROUND_WORK, "java.util.stream.BaseStream", "parallel"),
			new MemberBan(BACKGROUND_WORK, "java.util.Arrays", "parallel\\w+"),
			new MemberBan(PRINT_STACK_TRACE, "java.lang.Throwable", "printStackTrace"),
			new MemberBan(PRINT_STACK_TRACE, "java.lang.Thread", "dumpStack"),
			new MemberBan(LOCALE_LESS_CASE_CONVERSION, "java.lang.String", "toLowerCase|toUpperCase", 0, 0),
			new MemberBan(MULTI_ARGUMENT_URI, "java.net.URI", "<init>", 2, Integer.MAX_VALUE),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.lang.System",
					"setProperty|clearProperty|setProperties|setSecurityManager|setOut|setErr|setIn"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.security.Security",
					"setProperty|addProvider|insertProviderAt|removeProvider"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.util.Locale", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.util.TimeZone", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "javax.net.ssl.SSLContext", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.Authenticator", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.CookieHandler", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.ProxySelector", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.ResponseCache", "setDefault"),
			// Covers HttpsURLConnection's setDefaultHostnameVerifier and setDefaultSSLSocketFactory (a subtype), and
			// the instance method setDefaultUseCaches(boolean), which also sets the JVM-wide default.
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.URLConnection",
					"setDefault\\w*|setContentHandlerFactory|setFileNameMap"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.HttpURLConnection", "setFollowRedirects"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.URL", "setURLStreamHandlerFactory"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.Socket", "setSocketImplFactory"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.lang.Thread", "setDefaultUncaughtExceptionHandler"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.security.Policy", "setPolicy"));

	/**
	 * Banned supertypes for named classes (see {@link SupertypeBan}); instances of anonymous subclasses are caught by
	 * the constructor bans.
	 */
	static final List<SupertypeBan> SUPERTYPE_BANS = List.of(
			new SupertypeBan(BACKGROUND_WORK, "java.lang.Thread"),
			new SupertypeBan(BACKGROUND_WORK, "java.util.TimerTask"),
			new SupertypeBan(BACKGROUND_WORK, "java.util.concurrent.Executor"));

	private static final Map<String, Rule> RULES_BY_ID = MAIN_SOURCE_RULES.stream()
			.collect(Collectors.toMap(Rule::getId, rule -> rule, (first, second) -> first, LinkedHashMap::new));

	@Test
	void mainSourcesFollowSourcePolicy() throws IOException {
		ContractSupport.assertNoViolations("Source policy violations",
				findViolations(ContractSupport.repositoryRoot().resolve("src/main/java")));
	}

	@Test
	void everyDetectionBelongsToADeclaredRule() {
		for (MemberBan ban : MEMBER_BANS)
			Assertions.assertTrue(RULES_BY_ID.containsKey(ban.ruleId), ban::alternativeId);
		for (SupertypeBan ban : SUPERTYPE_BANS)
			Assertions.assertTrue(RULES_BY_ID.containsKey(ban.ruleId), ban::alternativeId);
	}

	@Test
	void repositoryNeverReferencesTheCompromisedSamlTestIdp() throws IOException {
		ContractSupport.assertNoViolations("Banned hostname found (plan 14.4: treat that public SAML test IdP as "
				+ "compromised; use RevetSec core's scripted IdP instead)",
				findBannedHostnames(ContractSupport.repositoryRoot()));
	}

	@Test
	void sourcesAndScriptsCarryTheLicenseHeader() throws IOException {
		Path root = ContractSupport.repositoryRoot();
		List<String> violations = new ArrayList<>();
		violations.addAll(findMissingLicenseHeaders(root.resolve("src/main/java")));
		violations.addAll(findMissingLicenseHeaders(root.resolve("src/test/java")));
		violations.addAll(findScriptsWithoutLicenseHeader(root));
		ContractSupport.assertNoViolations("Sources without the Revetware Apache-2.0 header", violations);
	}

	@Test
	void jarLegalFilesMatchTheRepository() throws IOException {
		Path root = ContractSupport.repositoryRoot();
		Path metaInf = root.resolve("src/main/resources/META-INF");

		Assertions.assertArrayEquals(Files.readAllBytes(root.resolve("LICENSE")),
				Files.readAllBytes(metaInf.resolve("LICENSE")),
				"src/main/resources/META-INF/LICENSE must be a byte-for-byte copy of LICENSE");

		Pattern jarNoticePattern = Pattern.compile(Pattern.quote(AdapterContract.PRODUCT_NAME)
				+ "\nCopyright 2026 Revetware LLC\\.?\n");
		String jarNotice = Files.readString(metaInf.resolve("NOTICE"), StandardCharsets.UTF_8);
		Assertions.assertTrue(jarNoticePattern.matcher(jarNotice).matches(), () -> "src/main/resources/META-INF/NOTICE "
				+ "must be exactly two lines, \"" + AdapterContract.PRODUCT_NAME + "\" and the Revetware copyright "
				+ "line, but was:\n" + jarNotice);

		Path repositoryNotice = root.resolve("NOTICE");
		Assertions.assertTrue(Files.isRegularFile(repositoryNotice), "The repository has no NOTICE file");
		String notice = Files.readString(repositoryNotice, StandardCharsets.UTF_8).replace("\r\n", "\n");
		Assertions.assertTrue(notice.startsWith(jarNotice),
				"NOTICE must begin with the same two lines as src/main/resources/META-INF/NOTICE");

		String pom = Files.readString(root.resolve("pom.xml"), StandardCharsets.UTF_8);
		Assertions.assertTrue(pom.contains("<name>" + AdapterContract.PRODUCT_NAME + "</name>"),
				() -> "pom.xml's <name> must be \"" + AdapterContract.PRODUCT_NAME + "\", as in NOTICE");
	}

	/**
	 * Applies every source-policy check to the Java files under {@code sourceRoot}. Each message is
	 * {@code <rule> <path>:<line>: <reason>}, one per rule and line, sorted by path, line and rule.
	 */
	static List<String> findViolations(Path sourceRoot) throws IOException {
		Map<String, Detection> byKey = new LinkedHashMap<>();
		for (Detection detection : findDetections(sourceRoot))
			byKey.putIfAbsent(detection.getKey(), detection);
		return byKey.values().stream()
				.sorted(Comparator.comparing((Detection detection) -> detection.path)
						.thenComparingInt(detection -> detection.line)
						.thenComparing(detection -> detection.ruleId))
				.map(detection -> detection.getKey() + ": " + rule(detection.ruleId).reason)
				.toList();
	}

	private static Rule rule(String ruleId) {
		@Nullable Rule rule = RULES_BY_ID.get(ruleId);
		if (rule == null)
			throw new IllegalStateException("Unknown source-policy rule " + ruleId);
		return rule;
	}

	/**
	 * Every alternative ID a detection can carry: each regular expression, each table entry, and the special checks.
	 */
	static List<String> alternativeIds() {
		List<String> alternativeIds = new ArrayList<>();
		for (Rule rule : MAIN_SOURCE_RULES)
			for (int index = 0; index < rule.alternatives.size(); ++index)
				alternativeIds.add(rule.alternativeId(index));
		MEMBER_BANS.forEach(ban -> alternativeIds.add(ban.alternativeId()));
		SUPERTYPE_BANS.forEach(ban -> alternativeIds.add(ban.alternativeId()));
		alternativeIds.addAll(List.of(SYNCHRONIZED_METHOD_ALTERNATIVE, SYNCHRONIZED_STATEMENT_ALTERNATIVE,
				PACKAGE_PATH_MISMATCH_ALTERNATIVE, MARKDOWN_DOC_COMMENT_ALTERNATIVE));
		return List.copyOf(alternativeIds);
	}

	/**
	 * Every raw finding under {@code sourceRoot}, with the alternative that produced it. A line can be found by more
	 * than one alternative; {@link #findViolations(Path)} reports it once.
	 */
	static List<Detection> findDetections(Path sourceRoot) throws IOException {
		List<Path> sources = ContractSupport.javaSources(sourceRoot);
		if (sources.isEmpty())
			return List.of();

		List<Detection> detections = new ArrayList<>();
		for (Path file : sources) {
			String relativePath = ContractSupport.relativePath(sourceRoot, file);
			ContractSupport.TranslatedSource translated = ContractSupport.translateUnicodeEscapes(
					Files.readString(file, StandardCharsets.UTF_8));
			List<Integer> lineCommentStarts = new ArrayList<>();
			String code = ContractSupport.stripCommentsAndStrings(translated, lineCommentStarts::add);

			// javac 23 and later read every line comment that starts with /// as a Markdown doc comment, whatever
			// precedes it on the line and however many slashes follow; javac 17 and 21 ignore it.
			String text = translated.getText();
			for (int start : lineCommentStarts)
				if (text.startsWith("///", start))
					detections.add(new Detection(MARKDOWN_DOC_COMMENT, relativePath,
							ContractSupport.lineNumber(text, start), MARKDOWN_DOC_COMMENT_ALTERNATIVE));

			for (Rule rule : MAIN_SOURCE_RULES) {
				for (int index = 0; index < rule.patterns.size(); ++index) {
					Matcher matcher = rule.patterns.get(index).matcher(code);
					while (matcher.find())
						detections.add(new Detection(rule.id, relativePath,
								ContractSupport.lineNumber(code, matcher.start()), rule.alternativeId(index)));
				}
			}
		}

		detections.addAll(ContractSupport.analyze(sourceRoot, null, SourcePolicyTests::findAttributedDetections));
		return List.copyOf(detections);
	}

	/**
	 * The javac-attributed checks: {@code synchronized}, {@link #MEMBER_BANS}, {@link #SUPERTYPE_BANS} and the
	 * package location of each file.
	 */
	private static List<Detection> findAttributedDetections(SourceAnalysis analysis) {
		List<Detection> detections = new ArrayList<>();
		Map<MemberBan, TypeElement> memberBanOwners = new LinkedHashMap<>();
		for (MemberBan ban : MEMBER_BANS)
			memberBanOwners.put(ban, ownerType(analysis, ban.owner));
		Map<SupertypeBan, TypeElement> supertypeBanOwners = new LinkedHashMap<>();
		for (SupertypeBan ban : SUPERTYPE_BANS)
			supertypeBanOwners.put(ban, ownerType(analysis, ban.owner));
		SourcePositions positions = analysis.getTrees().getSourcePositions();

		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits()) {
			String relativePath = analysis.relativePath(compilationUnit);

			String packagePath = ContractSupport.packageName(compilationUnit).replace('.', '/');
			int lastSlash = relativePath.lastIndexOf('/');
			String directory = lastSlash < 0 ? "" : relativePath.substring(0, lastSlash);
			if (!directory.equals(packagePath)) {
				@Nullable Tree packageTree = compilationUnit.getPackage();
				int line = packageTree == null ? 1 : analysis.lineNumber(compilationUnit,
						positions.getStartPosition(compilationUnit, packageTree));
				detections.add(new Detection(PACKAGE_PATH_MISMATCH, relativePath, line,
						PACKAGE_PATH_MISMATCH_ALTERNATIVE));
			}

			new TreePathScanner<Void, Void>() {
				@Override
				public @Nullable Void visitClass(ClassTree node, Void unused) {
					@Nullable Element element = analysis.getTrees().getElement(getCurrentPath());
					if (element instanceof TypeElement type && type.getNestingKind() != NestingKind.ANONYMOUS)
						for (Map.Entry<SupertypeBan, TypeElement> ban : supertypeBanOwners.entrySet())
							if (analysis.isSubtype(type, ban.getValue()))
								detect(ban.getKey().ruleId, node, ban.getKey().alternativeId());
					return super.visitClass(node, null);
				}

				@Override
				public @Nullable Void visitMethod(MethodTree node, Void unused) {
					if (node.getModifiers().getFlags().contains(Modifier.SYNCHRONIZED))
						detect(SYNCHRONIZED, node, SYNCHRONIZED_METHOD_ALTERNATIVE);
					return super.visitMethod(node, null);
				}

				@Override
				public @Nullable Void visitSynchronized(SynchronizedTree node, Void unused) {
					detect(SYNCHRONIZED, node, SYNCHRONIZED_STATEMENT_ALTERNATIVE);
					return super.visitSynchronized(node, null);
				}

				@Override
				public @Nullable Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
					// javac's generated default constructors call super() without source; the class check covers them.
					if (isWritten(node)) {
						ExpressionTree methodSelect = node.getMethodSelect();
						long position = positions.getStartPosition(compilationUnit, methodSelect);
						if (methodSelect instanceof MemberSelectTree memberSelect)
							position = Math.max(position, positions.getEndPosition(compilationUnit, memberSelect)
									- memberSelect.getIdentifier().length());
						checkMember(analysis.getTrees().getElement(new TreePath(getCurrentPath(), methodSelect)),
								position);
					}
					return super.visitMethodInvocation(node, null);
				}

				@Override
				public @Nullable Void visitNewClass(NewClassTree node, Void unused) {
					if (isWritten(node))
						checkMember(analysis.getTrees().getElement(getCurrentPath()),
								positions.getStartPosition(compilationUnit, node));
					return super.visitNewClass(node, null);
				}

				@Override
				public @Nullable Void visitMemberReference(MemberReferenceTree node, Void unused) {
					if (isWritten(node))
						checkMember(analysis.getTrees().getElement(getCurrentPath()),
								positions.getStartPosition(compilationUnit, node));
					return super.visitMemberReference(node, null);
				}

				private boolean isWritten(Tree node) {
					return positions.getEndPosition(compilationUnit, node) >= 0;
				}

				private void checkMember(@Nullable Element element, long position) {
					if (!(element instanceof ExecutableElement executable)
							|| !(executable.getEnclosingElement() instanceof TypeElement declaringType))
						return;
					String name = executable.getSimpleName().toString();
					int parameters = executable.getParameters().size();
					for (Map.Entry<MemberBan, TypeElement> entry : memberBanOwners.entrySet()) {
						MemberBan ban = entry.getKey();
						if (ban.names.matcher(name).matches() && parameters >= ban.minimumParameters
								&& parameters <= ban.maximumParameters
								&& analysis.isSubtype(declaringType, entry.getValue()))
							detect(ban.ruleId, position, ban.alternativeId());
					}
				}

				private void detect(String ruleId, Tree node, String alternativeId) {
					detect(ruleId, positions.getStartPosition(compilationUnit, node), alternativeId);
				}

				private void detect(String ruleId, long position, String alternativeId) {
					detections.add(new Detection(ruleId, relativePath, analysis.lineNumber(compilationUnit, position),
							alternativeId));
				}
			}.scan(compilationUnit, null);
		}

		return detections;
	}

	private static TypeElement ownerType(SourceAnalysis analysis, String qualifiedName) {
		@Nullable TypeElement owner = analysis.getElements().getTypeElement(qualifiedName);
		if (owner == null)
			throw new IllegalStateException("A source-policy ban names " + qualifiedName
					+ ", which javac cannot resolve");
		return owner;
	}

	/**
	 * Scans every file in the repository (see {@link ContractSupport#repositoryFiles(Path)}) for the hostname of the
	 * compromised public SAML test IdP. Text files are searched directly and inside their PEM and XML-signature
	 * base64 blocks, and report {@code path:line}. Binary files (any NUL byte) are searched as Latin-1 bytes, which
	 * finds ASCII inside DER or other binary data, and again with NUL bytes removed, which finds ASCII text encoded
	 * as UTF-16; they report the path alone.
	 */
	static List<String> findBannedHostnames(Path repositoryRoot) throws IOException {
		List<String> violations = new ArrayList<>();
		for (Path file : ContractSupport.repositoryFiles(repositoryRoot)) {
			String relativePath = ContractSupport.relativePath(repositoryRoot, file);
			byte[] bytes = Files.readAllBytes(file);
			String content = new String(bytes, StandardCharsets.ISO_8859_1);

			if (!ContractSupport.isProbablyText(bytes)) {
				if (BANNED_HOSTNAME.matcher(content).find() || BANNED_HOSTNAME.matcher(withoutNulBytes(bytes)).find())
					violations.add(relativePath + " (binary)");
				continue;
			}

			Matcher matcher = BANNED_HOSTNAME.matcher(content);
			while (matcher.find())
				violations.add(relativePath + ":" + ContractSupport.lineNumber(content, matcher.start()));

			Matcher blocks = BASE64_BLOCK.matcher(content);
			while (blocks.find()) {
				String body = blocks.group(1) != null ? blocks.group(1) : blocks.group(2);
				if (body != null && containsBannedHostname(decodeBase64(body)))
					violations.add(relativePath + ":" + ContractSupport.lineNumber(content, blocks.start())
							+ " (base64 block)");
			}
		}
		return List.copyOf(violations);
	}

	private static String withoutNulBytes(byte[] bytes) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(bytes.length);
		for (byte value : bytes)
			if (value != 0)
				outputStream.write(value);
		return new String(outputStream.toByteArray(), StandardCharsets.ISO_8859_1);
	}

	private static byte[] decodeBase64(String body) {
		try {
			return Base64.getDecoder().decode(body.replaceAll("\\s+", ""));
		} catch (IllegalArgumentException e) {
			return new byte[0];
		}
	}

	private static boolean containsBannedHostname(byte[] bytes) {
		return BANNED_HOSTNAME.matcher(new String(bytes, StandardCharsets.ISO_8859_1)).find()
				|| BANNED_HOSTNAME.matcher(withoutNulBytes(bytes)).find();
	}

	/**
	 * Returns the Java files under {@code sourceRoot} that do not begin with {@link ContractSupport#LICENSE_HEADER}.
	 */
	static List<String> findMissingLicenseHeaders(Path sourceRoot) throws IOException {
		List<String> violations = new ArrayList<>();
		for (Path file : ContractSupport.javaSources(sourceRoot)) {
			String content = Files.readString(file, StandardCharsets.UTF_8).replace("\r\n", "\n");
			if (!content.startsWith(ContractSupport.LICENSE_HEADER))
				violations.add(ContractSupport.relativePath(sourceRoot, file));
		}
		return List.copyOf(violations);
	}

	/**
	 * Returns the Python and shell scripts in the repository (see {@link ContractSupport#repositoryFiles(Path)})
	 * that do not begin, after an optional {@code #!} line, with {@link #SCRIPT_LICENSE_HEADER}.
	 */
	static List<String> findScriptsWithoutLicenseHeader(Path repositoryRoot) throws IOException {
		List<String> violations = new ArrayList<>();
		for (Path file : ContractSupport.repositoryFiles(repositoryRoot)) {
			String name = ContractSupport.fileName(file);
			if (!name.endsWith(".py") && !name.endsWith(".sh"))
				continue;
			String content = Files.readString(file, StandardCharsets.UTF_8).replace("\r\n", "\n");
			if (content.startsWith("#!"))
				content = content.substring(content.indexOf('\n') + 1);
			if (!content.startsWith(SCRIPT_LICENSE_HEADER))
				violations.add(ContractSupport.relativePath(repositoryRoot, file));
		}
		return List.copyOf(violations);
	}

	/**
	 * Visible for {@link ContractMetaTests}: the alternative IDs grouped by violation key.
	 */
	static Map<String, List<String>> alternativeIdsByKey(List<Detection> detections) {
		return detections.stream().collect(Collectors.groupingBy(Detection::getKey, LinkedHashMap::new,
				Collectors.mapping(Detection::getAlternativeId,
						Collectors.collectingAndThen(Collectors.toList(), ids -> ids.stream().distinct().sorted()
								.toList()))));
	}

	/**
	 * Visible for {@link ContractMetaTests}: rule IDs in declaration order.
	 */
	static List<String> ruleIds() {
		return MAIN_SOURCE_RULES.stream().map(Rule::getId).toList();
	}
}
