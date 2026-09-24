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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Meta-tests: each contract checker must report exactly the violations seeded under
 * {@code src/test/resources/contract-fixtures/}, no more (the compliant controls there) and no fewer. A checker
 * that silently stops matching, or loses one of its alternatives, fails here instead of passing vacuously on the
 * real sources.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ContractMetaTests {
	private static final String PACKAGE = AdapterContract.ADAPTER_PACKAGE;
	private static final String PACKAGE_PATH = AdapterContract.adapterPackagePath();
	private static final String BANNED_CALLS = PACKAGE_PATH + "/BannedCallsFixture.java";
	private static final String XML = PACKAGE_PATH + "/XmlFixture.java";

	/**
	 * An R1_EXCEPTIONS list for the public-api fixture, in place of the real (empty) one: an entry in the binary-name
	 * form that messages print, which exempts its type, plus the canonical {@code Outer.Nested} spelling of another
	 * nested type, which exempts nothing and must be reported as stale or misspelled.
	 */
	private static final Set<String> FIXTURE_R1_EXCEPTIONS = Set.of(
			PACKAGE + ".ListedErrorsFixture$LegacyError",
			PACKAGE + ".ListedErrorsFixture.RetiredError");

	private static Path fixture(String name) {
		Path fixture = ContractSupport.repositoryRoot().resolve("src/test/resources/contract-fixtures").resolve(name);
		Assertions.assertTrue(Files.isDirectory(fixture), () -> "Missing fixture directory " + fixture);
		return fixture;
	}

	private static Path coreStubs() {
		return fixture("core-stubs");
	}

	@Test
	void publicApiContractReportsExactlyTheSeededViolations() throws IOException {
		// The rendering of an annotated type in a nullness message differs across JDKs, so it is left out.
		List<String> violations = PublicApiContractTests.findViolations(fixture("public-api"), coreStubs(),
						FIXTURE_R1_EXCEPTIONS).stream()
				.map(violation -> violation.replaceFirst(" at .* \\(R2\\)$", " (R2)"))
				.toList();

		Assertions.assertEquals(Stream.of(
				"PublicApiContractTests.R1_EXCEPTIONS entry \"${package}.ListedErrorsFixture.RetiredError\": stale or "
						+ "misspelled entry; use the binary name (Outer$Nested, as violation messages print it) of an "
						+ "exported type in the analyzed sources",
				"${package}.InheritingFixture#newToken() (inherited from ${package}.AbstractBaseFixture): static "
						+ "factories are named builder(), withX(), fromX(), *Instance() or fromDefaults(), never "
						+ "of*, create* or new* (R1, NAMING_CONVENTIONS.md)",
				"${package}.InheritingFixture#parse(java.lang.String) (inherited from "
						+ "${package}.AbstractBaseFixture): public static method returns a verified type; only "
						+ "RevetSec core's validators may create one (R17)",
				"${package}.InheritingFixture#undated() (inherited from ${package}.AbstractBaseFixture): Javadoc has "
						+ "no @since tag (D28)",
				"${package}.InheritingFixture#undocumented(java.lang.String) (inherited from "
						+ "${package}.AbstractBaseFixture) parameter 0: lacks exactly one JSpecify "
						+ "@NonNull/@Nullable (R2)",
				"${package}.InheritingFixture#undocumented(java.lang.String) (inherited from "
						+ "${package}.AbstractBaseFixture) return type: lacks exactly one JSpecify "
						+ "@NonNull/@Nullable (R2)",
				"${package}.InheritingFixture#undocumented(java.lang.String) (inherited from "
						+ "${package}.AbstractBaseFixture): missing Javadoc (R20)",
				"${package}.ListedErrorsFixture$LegacyError#LegacyError(java.lang.String): public concrete types have "
						+ "private constructors (R1)",
				"${package}.ListedErrorsFixture$RetiredError: public concrete types are final, or sealed with only "
						+ "final or sealed permitted subclasses (R1)",
				"${package}.MissingMarkerFixture: must declare exactly one jsr305 thread-safety marker (@ThreadSafe, "
						+ "@NotThreadSafe or @Immutable); found []",
				"${package}.MissingNullnessFixture#createDefault(): static factories are named builder(), withX(), "
						+ "fromX(), *Instance() or fromDefaults(), never of*, create* or new* (R1, "
						+ "NAMING_CONVENTIONS.md)",
				"${package}.MissingNullnessFixture#nullableOptionalValue() return type type argument 0 (nested): "
						+ "lacks @NonNull (R2)",
				"${package}.MissingNullnessFixture#of(): static factories are named builder(), withX(), fromX(), "
						+ "*Instance() or fromDefaults(), never of*, create* or new* (R1, NAMING_CONVENTIONS.md)",
				"${package}.MissingNullnessFixture#unannotated(java.lang.String) parameter 0: lacks exactly one "
						+ "JSpecify @NonNull/@Nullable (R2)",
				"${package}.MissingNullnessFixture#unannotated(java.lang.String) return type: lacks exactly one "
						+ "JSpecify @NonNull/@Nullable (R2)",
				"${package}.MissingNullnessFixture#unannotatedTypeArgument() return type type argument 0 (nested): "
						+ "lacks exactly one JSpecify @NonNull/@Nullable (R2)",
				"${package}.OpenSealedFixture: sealed public concrete type permits the non-sealed subclass "
						+ "${package}.OpenSubclassFixture; every permitted subclass must be final or sealed (R1)",
				"${package}.PublicConstructorFixture#PublicConstructorFixture(): public concrete types have private "
						+ "constructors (R1)",
				"${package}.PublicConstructorFixture#PublicConstructorFixture(java.lang.String): public concrete "
						+ "types have private constructors (R1)",
				"${package}.PublicRecordFixture#PublicRecordFixture(java.lang.String): implicit public or protected "
						+ "constructor; declare every constructor explicitly (R1: public concrete types have private "
						+ "constructors)",
				"${package}.PublicRecordFixture: exported types must not be records; use a final class with getX() "
						+ "accessors (R1)",
				"${package}.TwoMarkersFixture: must declare exactly one jsr305 thread-safety marker (@ThreadSafe, "
						+ "@NotThreadSafe or @Immutable); found [javax.annotation.concurrent.Immutable, "
						+ "javax.annotation.concurrent.ThreadSafe]",
				"${package}.UndocumentedFixture (type): missing Javadoc (R20)",
				"${package}.UndocumentedFixture#UndocumentedFixture(): implicit public or protected constructor; "
						+ "declare every constructor explicitly (R1: public concrete types have private constructors)",
				"${package}.UndocumentedFixture#undated(): Javadoc has no @since tag (D28)",
				"${package}.UndocumentedFixture#undocumented(): missing Javadoc (R20)",
				"${package}.UndocumentedFixture: public concrete types are final, or sealed with only final or sealed "
						+ "permitted subclasses (R1)",
				"${package}.VerifiedTypeFactoryFixture#forge(): public static method returns a verified type; only "
						+ "RevetSec core's validators may create one (R17)",
				"${package}.VerifiedTypeFactoryFixture#jwtFor(java.lang.String): public static method returns a "
						+ "verified type; only RevetSec core's validators may create one (R17)",
				"${package}.VerifiedTypeFactoryFixture#jwtsFor(java.lang.String): public static method returns a "
						+ "verified type; only RevetSec core's validators may create one (R17)")
				.map(violation -> violation.replace("${package}", PACKAGE))
				.toList(), violations);
		Assertions.assertTrue(violations.stream().noneMatch(violation -> violation.contains("packagePrivateJwtFor")),
				"package-private methods are not API");
	}

	@Test
	void packageDependencyContractDetectsSeededViolations() throws IOException {
		List<String> violations = PackageDependencyTests.findViolations(fixture("package-dependencies"), coreStubs());

		assertReported(violations, PACKAGE_PATH + "/ImportsCoreInternalFixture.java:19: uses "
				+ "com.revetsec.internal.jose.InternalJoseFixture; adapters use only RevetSec core's public API");
		assertReported(violations, PACKAGE_PATH + "/ImportsCoreInternalFixture.java:29: uses com.revetsec.internal.jose;");
		assertReported(violations, PACKAGE_PATH + "/StaticImportCoreInternalFixture.java:19: uses "
				+ "com.revetsec.internal.jose.InternalJoseFixture.NAME;");
		assertReported(violations, PACKAGE_PATH + "/StaticImportCoreInternalFixture.java:29: uses "
				+ "com.revetsec.internal.jose;");
		assertReported(violations, PACKAGE_PATH + "/QualifiedCoreInternalFixture.java:27: uses "
				+ "com.revetsec.internal.jose;");
		assertReported(violations, PACKAGE + ".extra: adapters have exactly one package, " + PACKAGE);
		assertReported(violations, PACKAGE + ".extra: package-info.java is not annotated @NullMarked");
		assertReported(violations, PACKAGE + ".other: adapters have exactly one package, " + PACKAGE);
		assertReported(violations, PACKAGE + ".other: package has no package-info.java");

		assertNotReported(violations, "UsesCorePublicApiFixture");
		assertNotReported(violations, PACKAGE + ": ");
		assertNotReported(violations, "com.revetsec.oauth");
		Assertions.assertEquals(9, violations.size(), () -> String.join("\n", violations));
	}

	@Test
	void packageDependencyContractRequiresTheAdapterPackageInfo(@TempDir Path sourceRoot) throws IOException {
		Path packageDirectory = sourceRoot.resolve(PACKAGE_PATH);
		Files.createDirectories(packageDirectory);
		Files.writeString(packageDirectory.resolve("Helper.java"), ContractSupport.LICENSE_HEADER + "\npackage "
				+ PACKAGE + ";\n\nfinal class Helper {\n}\n", StandardCharsets.UTF_8);

		Assertions.assertEquals(List.of(PACKAGE + ": package has no package-info.java (R20)"),
				PackageDependencyTests.findViolations(sourceRoot, null));
	}

	@Test
	void sourcePolicyReportsExactlyTheSeededViolations() throws IOException {
		List<String> expected = new ArrayList<>();
		expect(expected, "background-work", BANNED_CALLS, 30, 31, 32, 33, 34, 35, 36, 41, 42, 44, 46, 47, 48, 49, 51,
				52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 165, 168, 174);
		expect(expected, "print-stack-trace", BANNED_CALLS, 68, 69, 70);
		expect(expected, "locale-less-case-conversion", BANNED_CALLS, 71, 72, 73, 75);
		expect(expected, "multi-argument-uri", BANNED_CALLS, 76);
		expect(expected, "default-http-client", BANNED_CALLS, 77, 78);
		expect(expected, "java-deserialization", BANNED_CALLS, 80, 81);
		expect(expected, "set-accessible", BANNED_CALLS, 82, 83, 84);
		expect(expected, "sun-internal-api", BANNED_CALLS, 85);
		expect(expected, "mime-base64-decoder", BANNED_CALLS, 86);
		expect(expected, "service-loader", BANNED_CALLS, 87, 146);
		expect(expected, "console-output", BANNED_CALLS, 88, 89, 90, 147);
		expect(expected, "insecure-random", BANNED_CALLS, 92, 93, 94, 95, 96, 97, 98);
		expect(expected, "jvm-global-mutation", BANNED_CALLS, IntStream.rangeClosed(103, 137).toArray());
		expect(expected, "markdown-doc-comment", BANNED_CALLS, 140, 142, 148);
		expect(expected, "insecure-random", PACKAGE_PATH + "/InsecureRandomFixture.java", 19, 20, 21, 22, 23, 31, 32,
				33, 34, 35);
		expect(expected, "synchronized", PACKAGE_PATH + "/SynchronizedFixture.java", 32, 36, 42, 43);
		expect(expected, "xpath", XML, 19, 33, 34);
		expect(expected, "xml-factory", XML, 27, 28, 29, 30, 31, 32, 33);
		expect(expected, "non-namespace-dom-lookup", XML, 35, 36);
		expect(expected, "package-path-mismatch", PACKAGE_PATH + "/other/MisplacedFixture.java", 17);

		List<String> reported = SourcePolicyTests.findViolations(fixture("source-policy")).stream()
				.map(violation -> violation.substring(0, violation.indexOf(": ")))
				.sorted()
				.toList();
		Assertions.assertEquals(expected.stream().sorted().toList(), reported);
	}

	/**
	 * Each regular-expression alternative, table entry and special check must have a seeded line that it alone
	 * reports, so dropping or breaking any one of them changes the exact result above.
	 */
	@Test
	void everySourcePolicyAlternativeHasItsOwnSeededLine() throws IOException {
		Map<String, List<String>> alternativesByLine = SourcePolicyTests.alternativeIdsByKey(
				SourcePolicyTests.findDetections(fixture("source-policy")));

		List<String> unexercised = SourcePolicyTests.alternativeIds().stream()
				.filter(alternative -> !alternativesByLine.containsValue(List.of(alternative)))
				.toList();
		Assertions.assertEquals(List.of(), unexercised,
				"Alternatives without a seeded line that only they report: " + unexercised);
		List<String> reportedRules = alternativesByLine.keySet().stream()
				.map(key -> key.substring(0, key.indexOf(' ')))
				.distinct()
				.sorted()
				.toList();
		Assertions.assertEquals(SourcePolicyTests.ruleIds().stream().sorted().toList(), reportedRules,
				"Every rule needs a seeded violation");
	}

	@Test
	void unicodeEscapesTranslateAsJavacTranslatesThem() {
		Assertions.assertEquals("System", translated("\\u0053ystem"));
		Assertions.assertEquals("System", translated("\\uuu0053ystem"));
		Assertions.assertEquals("\\\\u0053", translated("\\\\u0053"), "an escaped backslash does not start an escape");
		Assertions.assertEquals("\\\\S", translated("\\\\\\u0053"),
				"a backslash after an even number of backslashes does");
		Assertions.assertEquals("\\u00zz", translated("\\u00zz"));

		ContractSupport.TranslatedSource escapedNewline = ContractSupport.translateUnicodeEscapes("a\\u000ab");
		Assertions.assertEquals("a b", escapedNewline.getText(), "line numbers must not move");
		Assertions.assertTrue(escapedNewline.isEscapedLineTerminator(1));
		Assertions.assertFalse(escapedNewline.isEscapedLineTerminator(0));
		Assertions.assertEquals("  x", ContractSupport.stripCommentsAndStrings(
				ContractSupport.translateUnicodeEscapes("// comment \\u000a x")),
				"an escaped newline ends a line comment");

		// U+FFFF, escaped or not, is an ordinary character: it neither ends a literal nor a comment.
		for (String noncharacter : List.of("\\uFFFF", "\uFFFF")) {
			ContractSupport.TranslatedSource source = ContractSupport.translateUnicodeEscapes(
					"a(\"" + noncharacter + "\") || b(\"System.out\"); // " + noncharacter + " System.err");
			Assertions.assertEquals("a(\"\") || b(\"\"); ", ContractSupport.stripCommentsAndStrings(source));
			Assertions.assertFalse(source.isEscapedLineTerminator(3));
		}
	}

	private static String translated(String source) {
		return ContractSupport.translateUnicodeEscapes(source).getText();
	}

	@Test
	void bannedHostnameScanSearchesTextBinaryAndBase64Content(@TempDir Path repository) throws IOException {
		String hostname = String.join(".", "saml" + "test", "id");
		byte[] certificate = derLike(hostname);
		write(repository, "docs/partners.md", "Line one\nSee https://" + hostname + "/idp\n");
		write(repository, "clean.txt", "Nothing to see.\n");
		write(repository, "binary.bin", new byte[]{0, 1, 2, 's', 'a', 'm', 'l'});
		write(repository, "fixtures/idp/idp-cert.der", certificate);
		write(repository, "fixtures/idp/metadata-utf16le.xml",
				("<EntityDescriptor entityID=\"https://" + hostname + "/\"/>").getBytes(StandardCharsets.UTF_16LE));
		write(repository, "fixtures/idp/metadata-utf16be.xml",
				("<EntityDescriptor entityID=\"https://" + hostname + "/\"/>").getBytes(StandardCharsets.UTF_16));
		write(repository, "fixtures/idp/idp-cert.pem", "-----BEGIN CERTIFICATE-----\n"
				+ Base64.getMimeEncoder().encodeToString(certificate) + "\n-----END CERTIFICATE-----\n");
		write(repository, "fixtures/idp/metadata.xml", "<md:EntityDescriptor>\n<ds:X509Certificate>"
				+ Base64.getEncoder().encodeToString(certificate) + "</ds:X509Certificate>\n</md:EntityDescriptor>\n");
		write(repository, "fixtures/other-cert.pem", "-----BEGIN CERTIFICATE-----\n"
				+ Base64.getEncoder().encodeToString(derLike("example.com")) + "\n-----END CERTIFICATE-----\n");
		// Without a git listing, build-output directories are skipped wherever they are.
		write(repository, "target/ignored.txt", hostname);
		write(repository, "fixtures/idp/target/ignored.txt", hostname);

		Assertions.assertEquals(List.of(
				"docs/partners.md:2",
				"fixtures/idp/idp-cert.der (binary)",
				"fixtures/idp/idp-cert.pem:1 (base64 block)",
				"fixtures/idp/metadata-utf16be.xml (binary)",
				"fixtures/idp/metadata-utf16le.xml (binary)",
				"fixtures/idp/metadata.xml:2 (base64 block)"), SourcePolicyTests.findBannedHostnames(repository));
	}

	@Test
	void repositoryScansFollowWhatGitWouldTrack(@TempDir Path repository) throws IOException {
		Assumptions.assumeTrue(git(repository, "init", "-q") && git(repository, "config", "core.excludesFile",
				".git/no-global-excludes"), "git is not available");
		String hostname = String.join(".", "saml" + "test", "id");
		write(repository, ".gitignore", "/target/\n");
		write(repository, "target/ignored.txt", hostname);
		write(repository, "fixtures/idp/target/metadata.xml", "<EntityDescriptor entityID=\"https://" + hostname
				+ "/\"/>\n");
		write(repository, "tools/node_modules/sample/README.md", "Mirror of https://" + hostname + "\n");

		Assertions.assertEquals(List.of(
				"fixtures/idp/target/metadata.xml:1",
				"tools/node_modules/sample/README.md:1"), SourcePolicyTests.findBannedHostnames(repository));
	}

	@Test
	void licenseHeaderCheckDetectsMissingHeader(@TempDir Path sourceRoot) throws IOException {
		Files.createDirectories(sourceRoot.resolve(PACKAGE_PATH));
		Files.writeString(sourceRoot.resolve(PACKAGE_PATH + "/WithHeader.java"),
				ContractSupport.LICENSE_HEADER + "\npackage " + PACKAGE + ";\n", StandardCharsets.UTF_8);
		Files.writeString(sourceRoot.resolve(PACKAGE_PATH + "/WithoutHeader.java"), "package " + PACKAGE + ";\n",
				StandardCharsets.UTF_8);

		Assertions.assertEquals(List.of(PACKAGE_PATH + "/WithoutHeader.java"),
				SourcePolicyTests.findMissingLicenseHeaders(sourceRoot));
	}

	@Test
	void scriptLicenseHeaderCheckDetectsMissingHeader(@TempDir Path repository) throws IOException {
		Files.createDirectories(repository.resolve("scripts"));
		Files.writeString(repository.resolve("scripts/with-shebang.py"),
				"#!/usr/bin/env python3\n" + SourcePolicyTests.SCRIPT_LICENSE_HEADER + "\nprint()\n",
				StandardCharsets.UTF_8);
		Files.writeString(repository.resolve("scripts/without-shebang.sh"),
				SourcePolicyTests.SCRIPT_LICENSE_HEADER + "\necho\n", StandardCharsets.UTF_8);
		Files.writeString(repository.resolve("scripts/missing.py"), "print()\n", StandardCharsets.UTF_8);
		Files.writeString(repository.resolve("scripts/notes.txt"), "Not a script.\n", StandardCharsets.UTF_8);

		Assertions.assertTrue(SourcePolicyTests.SCRIPT_LICENSE_HEADER.startsWith("# Copyright 2026 Revetware LLC.\n#\n"),
				SourcePolicyTests.SCRIPT_LICENSE_HEADER);
		Assertions.assertEquals(List.of("scripts/missing.py"),
				SourcePolicyTests.findScriptsWithoutLicenseHeader(repository));
	}

	@Test
	void claimsLintReportsExactlyTheSeededClaimsAndAllowlistProblems(@TempDir Path repository) throws IOException {
		copyFixture("claims", repository);
		Files.createDirectories(repository.resolve("target"));
		Files.writeString(repository.resolve("target/ignored.md"), "Excluded build output: certified.\n",
				StandardCharsets.UTF_8);
		Files.createDirectories(repository.resolve("docs/images"));
		Files.write(repository.resolve("docs/images/openid-certified-mark.png"), new byte[]{(byte) 0x89, 'P', 'N', 'G'});
		Files.write(repository.resolve("docs/images/openid-connect-login-flow.svg"), new byte[]{'<', 's', 'v', 'g', '>'});

		// The context quoted after " in " is for readers; it is left out here.
		List<String> violations = ClaimsLintTests.findViolations(repository).stream()
				.map(violation -> violation.contains(" in \"") ? violation.substring(0, violation.indexOf(" in \""))
						: violation)
				.toList();

		Assertions.assertEquals(List.of(
				"docs/images/openid-certified-mark.png: OpenID Foundation logo files are not allowed without a "
						+ "certification (plan 19)",
				"claims-allowlist.txt:7: malformed entry; expected <relative-path>|<exact "
						+ "substring>|<evidence-or-reason>",
				"claims-allowlist.txt:8 (README.md|independently): too broad; quote the approved wording, with at "
						+ "least 2 words besides the banned terms, so the entry cannot allow later uses of the term "
						+ "(plan 19)",
				"claims-allowlist.txt:9 (README.md|been independently audited): too broad; quote the approved "
						+ "wording, with at least 2 words besides the banned terms, so the entry cannot allow later "
						+ "uses of the term (plan 19)",
				"claims-allowlist.txt:4 (README.md|This sentence does not appear anywhere.): stale; the substring no "
						+ "longer appears in README.md",
				"claims-allowlist.txt:5 (README.md|the conformance suite): stale; the substring contains no banned "
						+ "term",
				"claims-allowlist.txt:6 (docs/missing.md|anything): stale; docs/missing.md does not exist or is not "
						+ "a scanned file",
				"README.md:3: banned claim term 'production-ready'",
				"README.md:8: banned claim term 'battle-tested'",
				"README.md:13: banned claim term 'FIPS'",
				"README.md:17: banned claim term 'production-ready'",
				"README.md:18: banned claim term 'battle-tested'",
				"README.md:21: banned claim term 'production-ready'",
				"README.md:21: banned claim term 'production-proven'",
				"README.md:23: banned claim term 'production-ready'",
				"README.md:23: banned claim term 'pen-tested'",
				"docs/guide.md:3: banned claim term 'more secure than'",
				"docs/guide.md:5: banned claim term 'more secure than'",
				"pom.xml:8: banned claim term 'battle-tested'",
				"src/main/java/com/revetsec/DocFixture.java:20: banned claim term 'compliant'",
				"src/main/java/com/revetsec/DocFixture.java:21: banned claim term 'production-ready'",
				"src/main/java/com/revetsec/DocFixture.java:22: banned claim term 'pen-tested'",
				"src/main/java/com/revetsec/DocFixture.java:33: banned claim term 'conformant'",
				"src/main/java/com/revetsec/doc-files/notes.html:3: banned claim term 'battle-tested'",
				"src/main/java/com/revetsec/package.html:3: banned claim term 'audited'",
				"src/main/javadoc/overview.html:4: banned claim term 'certified'",
				"src/main/javadoc/overview.html:5: banned claim term 'production-ready'"), violations);
	}

	@Test
	void claimsLintTreatsMissingAllowlistAsEmpty(@TempDir Path repository) throws IOException {
		copyFixture("claims", repository);
		Files.delete(repository.resolve(ClaimsLintTests.ALLOWLIST_FILE));

		List<String> violations = ClaimsLintTests.findViolations(repository);

		assertReported(violations, "README.md:5: banned claim term 'independently'");
		assertReported(violations, "README.md:6: banned claim term 'audited'");
		assertNotReported(violations, ClaimsLintTests.ALLOWLIST_FILE);
	}

	@Test
	void claimsLintCoversEveryPlannedTerm() {
		Assertions.assertEquals(
				List.of("FIPS", "audited", "battle-tested", "certified", "compliant", "conformant", "independently",
						"more secure than", "pen-tested", "production-proven", "production-ready"),
				List.copyOf(ClaimsLintTests.bannedTermNames()));
	}

	private static void expect(List<String> expected, String ruleId, String path, int... lines) {
		for (int line : lines)
			expected.add(ruleId + " " + path + ":" + line);
	}

	/**
	 * A few bytes shaped like a DER certificate, with {@code name} as an ASCII string inside.
	 */
	private static byte[] derLike(String name) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.writeBytes(new byte[]{0x30, (byte) 0x82, 0x01, 0x0a, 0x30, 0x00, 0x13, (byte) name.length()});
		outputStream.writeBytes(name.getBytes(StandardCharsets.US_ASCII));
		outputStream.writeBytes(new byte[]{0x00, 0x01, 0x02});
		return outputStream.toByteArray();
	}

	private static void write(Path root, String relativePath, String content) throws IOException {
		write(root, relativePath, content.getBytes(StandardCharsets.UTF_8));
	}

	private static void write(Path root, String relativePath, byte[] content) throws IOException {
		Path file = root.resolve(relativePath);
		Files.createDirectories(file.getParent());
		Files.write(file, content);
	}

	/**
	 * Runs git in {@code directory}; returns whether it ran and succeeded.
	 */
	private static boolean git(Path directory, String... arguments) {
		List<String> command = new ArrayList<>(List.of("git", "-C", directory.toString()));
		command.addAll(List.of(arguments));
		try {
			Process process = new ProcessBuilder(command).redirectErrorStream(true)
					.redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
			if (!process.waitFor(60, TimeUnit.SECONDS)) {
				process.destroyForcibly();
				return false;
			}
			return process.exitValue() == 0;
		} catch (IOException e) {
			return false;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	private static void copyFixture(String name, Path target) throws IOException {
		Path source = fixture(name);
		try (Stream<Path> paths = Files.walk(source)) {
			for (Path path : paths.toList()) {
				Path destination = target.resolve(ContractSupport.relativePath(source, path));
				if (Files.isDirectory(path))
					Files.createDirectories(destination);
				else
					Files.copy(path, destination);
			}
		}
	}

	private static void assertReported(List<String> violations, String expectedFragment) {
		Assertions.assertTrue(violations.stream().anyMatch(violation -> violation.contains(expectedFragment)),
				() -> "Expected a violation containing \"" + expectedFragment + "\" but found:\n - "
						+ String.join("\n - ", violations));
	}

	private static void assertNotReported(List<String> violations, String unexpectedFragment) {
		Assertions.assertTrue(violations.stream().noneMatch(violation -> violation.contains(unexpectedFragment)),
				() -> "Expected no violation containing \"" + unexpectedFragment + "\" but found:\n - "
						+ String.join("\n - ", violations));
	}
}
