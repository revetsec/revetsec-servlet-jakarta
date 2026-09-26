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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Claims discipline (plan 19, 14.6): Revetsec's documents never call it certified, compliant, conformant, audited,
 * production-ready, FIPS and so on, unless an allowlist entry pairs the exact wording with its evidence.
 * <p>
 * Scanned text:
 * <ul>
 *   <li>every {@code *.md} file in the repository, except {@code release/SECURITY_CLAIMS_AUDIT.md} (it lists
 *   rejected claims) and the seeded violations under {@code src/test/resources/contract-fixtures/};</li>
 *   <li>everything that ends up in the published Javadoc: documentation comments in {@code src/main/java}
 *   ({@code /** *}{@code /} and Markdown {@code ///} comments), {@code package.html} files and HTML under
 *   {@code doc-files/} there, and the HTML under {@code src/main/javadoc/} (the overview page);</li>
 *   <li>the POM's {@code <name>} and {@code <description>};</li>
 *   <li>the Playground's HTML templates ({@code examples/**}{@code /*.html}).</li>
 * </ul>
 * Banned terms match case-insensitively on word boundaries. Multi-word terms match across any run of whitespace
 * (line breaks, indentation, no-break spaces and a Javadoc line's {@code *} included) with at most one hyphen or
 * dash (en dash, non-breaking hyphen, minus and so on) among it; HTML entities for spaces and dashes (named, such
 * as nbsp and ndash, or numeric) count as the characters they stand for. {@code certified} also covers
 * "OpenID Certified", and {@code compliant} covers "OAuth 2.1 compliant" and "SAML 2.0 compliant". Image files that
 * look like OpenID Foundation marks (a name containing "oidf", or "openid" with "logo", "mark", "certif" or
 * "badge") are rejected outright: no OIDF logo without a certification.
 * <p>
 * The allowlist is {@value #ALLOWLIST_FILE} at the repository root (absent means empty). Each non-blank line that
 * does not start with {@code #} is {@code <relative-path>|<exact substring>|<evidence-or-reason>}: the path is
 * everything before the first {@code |}, the reason everything after the last {@code |}, and the substring what
 * lies between (so the substring may contain {@code |}, but the reason may not). Fields are trimmed. The
 * substring is matched case-sensitively, but any run of whitespace in it matches any run of whitespace in the
 * file, so wrapped lines still match. An entry allows a banned term only where the term lies entirely inside an
 * occurrence of the substring. Entries that do not match, or match without covering a banned term, are stale and
 * fail the test. An entry must quote the approved wording, not just the term: a substring with a banned term but
 * fewer than {@value #MINIMUM_ALLOWLIST_CONTEXT_WORDS} other words is rejected as too broad, because it would allow
 * every later use of the term in that file.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ClaimsLintTests {
	static final String ALLOWLIST_FILE = "claims-allowlist.txt";
	static final String CLAIMS_AUDIT_FILE = "release/SECURITY_CLAIMS_AUDIT.md";
	static final String CONTRACT_FIXTURES = "src/test/resources/contract-fixtures/";

	/**
	 * Words an allowlist substring needs besides its banned terms.
	 */
	static final int MINIMUM_ALLOWLIST_CONTEXT_WORDS = 2;

	private static final String WORD_START = "(?<![\\p{L}\\p{N}_])";
	private static final String WORD_END = "(?![\\p{L}\\p{N}_])";
	/**
	 * Between the words of a multi-word term: any whitespace (Unicode, so no-break spaces too) around at most one
	 * hyphen or dash.
	 */
	private static final String JOINER = "\\s*[-\\u2010-\\u2015\\u2212\\uFE58\\uFE63\\uFF0D]?\\s*";
	private static final Pattern WHITESPACE = Pattern.compile("\\s+", Pattern.UNICODE_CHARACTER_CLASS);
	private static final Pattern WORD = Pattern.compile("\\p{L}+");
	private static final Pattern HTML_ENTITY = Pattern.compile("&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z]+);");
	private static final Set<String> SPACE_ENTITIES = Set.of("nbsp", "ensp", "emsp", "emsp13", "emsp14", "numsp",
			"puncsp", "thinsp", "hairsp", "nnbsp");
	private static final Set<String> DASH_ENTITIES = Set.of("ndash", "mdash", "hyphen", "dash", "minus", "horbar");
	private static final Pattern LOGO_FILE = Pattern.compile("(?i)(?:.*oidf.*|.*openid.*(?:logo|mark|certif|badge).*"
			+ "|.*(?:logo|mark|certif|badge).*openid.*)\\.(?:png|svg|jpe?g|gif|webp|ico|pdf|eps)");
	private static final Pattern POM_NAME = Pattern.compile("<name>(.*?)</name>", Pattern.DOTALL);
	private static final Pattern POM_DESCRIPTION = Pattern.compile("<description>(.*?)</description>", Pattern.DOTALL);

	/**
	 * The banned terms of plan 14.6.
	 */
	static final Map<String, Pattern> BANNED_TERMS = bannedTerms(
			"certified", "certified",
			"compliant", "compliant",
			"conformant", "conformant",
			"audited", "audited",
			"independently", "independently",
			"pen-tested", "pen" + JOINER + "tested",
			"FIPS", "fips",
			"production-proven", "production" + JOINER + "proven",
			"production-ready", "production" + JOINER + "ready",
			"battle-tested", "battle" + JOINER + "tested",
			"more secure than", "more\\s+secure\\s+than");

	private static Map<String, Pattern> bannedTerms(String... termsAndRegexes) {
		Map<String, Pattern> terms = new LinkedHashMap<>();
		for (int index = 0; index < termsAndRegexes.length; index += 2)
			terms.put(termsAndRegexes[index], Pattern.compile(WORD_START + termsAndRegexes[index + 1] + WORD_END,
					Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.UNICODE_CHARACTER_CLASS));
		return terms;
	}

	@Test
	void repositoryDocumentsMakeNoUnsupportedClaims() throws IOException {
		ContractSupport.assertNoViolations("Claims-lint violations (plan 19): reword, or add an allowlist entry with "
						+ "evidence to " + ALLOWLIST_FILE,
				findViolations(ContractSupport.repositoryRoot(), Set.of(CONTRACT_FIXTURES)));
	}

	/**
	 * Lints the repository at {@code repositoryRoot} against its {@value #ALLOWLIST_FILE}.
	 */
	static List<String> findViolations(Path repositoryRoot) throws IOException {
		return findViolations(repositoryRoot, Set.of());
	}

	/**
	 * Lints the repository at {@code repositoryRoot}, skipping files whose relative path starts with one of
	 * {@code excludedPrefixes}.
	 */
	static List<String> findViolations(Path repositoryRoot, Set<String> excludedPrefixes) throws IOException {
		List<String> violations = new ArrayList<>();
		Map<String, String> scannedText = new LinkedHashMap<>();

		for (Path file : ContractSupport.repositoryFiles(repositoryRoot)) {
			String relativePath = ContractSupport.relativePath(repositoryRoot, file);
			if (relativePath.equals(CLAIMS_AUDIT_FILE)
					|| excludedPrefixes.stream().anyMatch(relativePath::startsWith))
				continue;

			if (LOGO_FILE.matcher(ContractSupport.fileName(file)).matches()) {
				violations.add(relativePath + ": OpenID Foundation logo files are not allowed without a certification "
						+ "(plan 19)");
				continue;
			}

			@Nullable String text = scannedText(relativePath, file);
			if (text != null)
				scannedText.put(relativePath, withEntitiesResolved(text));
		}

		Map<String, List<Match>> matches = new LinkedHashMap<>();
		for (Map.Entry<String, String> entry : scannedText.entrySet())
			matches.put(entry.getKey(), bannedTermMatches(entry.getValue()));

		for (AllowlistEntry allowlistEntry : readAllowlist(repositoryRoot.resolve(ALLOWLIST_FILE), violations)) {
			@Nullable String text = scannedText.get(allowlistEntry.path);
			if (text == null) {
				violations.add(allowlistEntry.describe() + ": stale; " + allowlistEntry.path
						+ " does not exist or is not a scanned file");
				continue;
			}
			Matcher matcher = allowlistEntry.pattern.matcher(text);
			boolean found = false;
			boolean coveredAny = false;
			while (matcher.find()) {
				found = true;
				for (Match match : matches.getOrDefault(allowlistEntry.path, List.of()))
					if (match.start >= matcher.start() && match.end <= matcher.end()) {
						match.covered = true;
						coveredAny = true;
					}
			}
			if (!found)
				violations.add(allowlistEntry.describe() + ": stale; the substring no longer appears in "
						+ allowlistEntry.path);
			else if (!coveredAny)
				violations.add(allowlistEntry.describe() + ": stale; the substring contains no banned term");
		}

		for (Map.Entry<String, List<Match>> entry : matches.entrySet()) {
			String text = scannedText.getOrDefault(entry.getKey(), "");
			for (Match match : entry.getValue())
				if (!match.covered)
					violations.add(entry.getKey() + ":" + ContractSupport.lineNumber(text, match.start)
							+ ": banned claim term '" + match.term + "' in \"" + context(text, match) + "\"");
		}

		return List.copyOf(violations);
	}

	/**
	 * Returns the text of {@code file} to lint, with unscanned characters blanked so offsets and lines still match
	 * the file, or {@code null} if the file is not linted.
	 */
	private static @Nullable String scannedText(String relativePath, Path file) throws IOException {
		String lowerCasePath = relativePath.toLowerCase(Locale.ROOT);
		boolean html = lowerCasePath.endsWith(".html") || lowerCasePath.endsWith(".htm");
		if (lowerCasePath.endsWith(".md"))
			return Files.readString(file, StandardCharsets.UTF_8);
		if (lowerCasePath.startsWith("examples/") && html)
			return Files.readString(file, StandardCharsets.UTF_8);
		if (relativePath.startsWith("src/main/javadoc/") && html)
			return Files.readString(file, StandardCharsets.UTF_8);
		if (relativePath.startsWith("src/main/java/") && html
				&& (lowerCasePath.contains("/doc-files/") || lowerCasePath.endsWith("/package.html")))
			return Files.readString(file, StandardCharsets.UTF_8);
		if (relativePath.startsWith("src/main/java/") && lowerCasePath.endsWith(".java"))
			return ContractSupport.javadocText(Files.readString(file, StandardCharsets.UTF_8));
		if (relativePath.equals("pom.xml"))
			return pomText(Files.readString(file, StandardCharsets.UTF_8));
		return null;
	}

	/**
	 * Replaces each HTML entity for a space or a dash (named, such as nbsp or ndash, or numeric, such as 160) by a
	 * space or a hyphen padded with spaces to the entity's length, so offsets and lines still match the file. Other
	 * entities are left alone.
	 */
	private static String withEntitiesResolved(String text) {
		Matcher matcher = HTML_ENTITY.matcher(text);
		if (!matcher.find())
			return text;
		StringBuilder resolved = new StringBuilder(text);
		do {
			String name = matcher.group(1);
			int codePoint = -1;
			if (name.startsWith("#x") || name.startsWith("#X"))
				codePoint = Integer.parseInt(name.substring(2), 16);
			else if (name.startsWith("#"))
				codePoint = Integer.parseInt(name.substring(1));
			boolean space = SPACE_ENTITIES.contains(name) || (codePoint >= 0 && Character.isValidCodePoint(codePoint)
					&& (Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint)));
			boolean dash = DASH_ENTITIES.contains(name) || codePoint == '-' || codePoint == 0x2212
					|| (codePoint >= 0 && Character.isValidCodePoint(codePoint)
					&& Character.getType(codePoint) == Character.DASH_PUNCTUATION);
			if (space || dash) {
				for (int index = matcher.start(); index < matcher.end(); ++index)
					resolved.setCharAt(index, ' ');
				if (dash)
					resolved.setCharAt(matcher.start(), '-');
			}
		} while (matcher.find());
		return resolved.toString();
	}

	/**
	 * The project's name and description: the first {@code <name>} and {@code <description>} elements, which in a
	 * Maven POM precede the nested license and developer names.
	 */
	private static String pomText(String pom) {
		char[] masked = new char[pom.length()];
		for (int index = 0; index < masked.length; ++index)
			masked[index] = pom.charAt(index) == '\n' ? '\n' : ' ';
		for (Pattern pattern : List.of(POM_NAME, POM_DESCRIPTION)) {
			Matcher matcher = pattern.matcher(pom);
			if (matcher.find())
				for (int index = matcher.start(1); index < matcher.end(1); ++index)
					masked[index] = pom.charAt(index);
		}
		return new String(masked);
	}

	private static List<Match> bannedTermMatches(String text) {
		List<Match> matches = new ArrayList<>();
		for (Map.Entry<String, Pattern> term : BANNED_TERMS.entrySet()) {
			Matcher matcher = term.getValue().matcher(text);
			while (matcher.find())
				matches.add(new Match(term.getKey(), matcher.start(), matcher.end()));
		}
		matches.sort((first, second) -> Integer.compare(first.start, second.start));
		return matches;
	}

	private static String context(String text, Match match) {
		int start = Math.max(0, match.start - 40);
		int end = Math.min(text.length(), match.end + 40);
		return WHITESPACE.matcher(text.substring(start, end)).replaceAll(" ").trim();
	}

	private static List<AllowlistEntry> readAllowlist(Path allowlistFile, List<String> violations) throws IOException {
		if (!Files.isRegularFile(allowlistFile))
			return List.of();

		List<AllowlistEntry> entries = new ArrayList<>();
		List<String> lines = Files.readAllLines(allowlistFile, StandardCharsets.UTF_8);
		for (int index = 0; index < lines.size(); ++index) {
			String line = lines.get(index).strip();
			if (line.isEmpty() || line.startsWith("#"))
				continue;
			int firstBar = line.indexOf('|');
			int lastBar = line.lastIndexOf('|');
			if (firstBar < 0 || lastBar == firstBar) {
				violations.add(ALLOWLIST_FILE + ":" + (index + 1) + ": malformed entry; expected "
						+ "<relative-path>|<exact substring>|<evidence-or-reason>");
				continue;
			}
			String path = line.substring(0, firstBar).strip();
			String substring = line.substring(firstBar + 1, lastBar).strip();
			String reason = line.substring(lastBar + 1).strip();
			if (path.isEmpty() || substring.isEmpty() || reason.isEmpty()) {
				violations.add(ALLOWLIST_FILE + ":" + (index + 1) + ": malformed entry; the path, substring and "
						+ "evidence-or-reason must all be non-empty");
				continue;
			}
			if (isTooBroad(substring)) {
				violations.add(ALLOWLIST_FILE + ":" + (index + 1) + " (" + path + "|" + substring + "): too broad; "
						+ "quote the approved wording, with at least " + MINIMUM_ALLOWLIST_CONTEXT_WORDS + " words "
						+ "besides the banned terms, so the entry cannot allow later uses of the term (plan 19)");
				continue;
			}
			entries.add(new AllowlistEntry(index + 1, path, substring));
		}
		return entries;
	}

	/**
	 * Returns whether {@code substring} contains a banned term but fewer than
	 * {@value #MINIMUM_ALLOWLIST_CONTEXT_WORDS} words outside its banned-term matches. (A substring with no banned
	 * term allows nothing; it is reported as stale instead.)
	 */
	private static boolean isTooBroad(String substring) {
		StringBuilder remainder = new StringBuilder(WHITESPACE.matcher(substring).replaceAll(" ").strip());
		boolean bannedTerm = false;
		for (Pattern pattern : BANNED_TERMS.values()) {
			Matcher matcher = pattern.matcher(remainder);
			while (matcher.find()) {
				bannedTerm = true;
				for (int index = matcher.start(); index < matcher.end(); ++index)
					remainder.setCharAt(index, ' ');
			}
		}
		return bannedTerm && WORD.matcher(remainder).results().count() < MINIMUM_ALLOWLIST_CONTEXT_WORDS;
	}

	private static final class Match {
		private final String term;
		private final int start;
		private final int end;
		private boolean covered;

		private Match(String term, int start, int end) {
			this.term = term;
			this.start = start;
			this.end = end;
		}
	}

	private static final class AllowlistEntry {
		private final int lineNumber;
		private final String path;
		private final String substring;
		private final Pattern pattern;

		private AllowlistEntry(int lineNumber, String path, String substring) {
			this.lineNumber = lineNumber;
			this.path = path;
			this.substring = substring;
			this.pattern = Pattern.compile(Arrays.stream(WHITESPACE.split(substring))
					.filter(token -> !token.isEmpty())
					.map(Pattern::quote)
					.collect(Collectors.joining("\\s+")), Pattern.UNICODE_CHARACTER_CLASS);
		}

		private String describe() {
			return ALLOWLIST_FILE + ":" + this.lineNumber + " (" + this.path + "|" + this.substring + ")";
		}
	}

	/**
	 * Visible for {@link ContractMetaTests}: the banned-term names.
	 */
	static Set<String> bannedTermNames() {
		return new TreeSet<>(BANNED_TERMS.keySet());
	}
}
