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

import com.google.errorprone.annotations.CheckReturnValue;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.DocTrees;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePath;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Shared machinery for the adapter's source-inventory contract tests, adapted from Revetsec core's.
 * <p>
 * Every checker is pure JDK ({@code javax.tools}, {@code com.sun.source}) plus JUnit assertions, and takes the
 * root it inspects as a parameter so {@link ContractMetaTests} can point it at seeded violations.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ContractSupport {
	/**
	 * The Apache-2.0 header every Java source file starts with (M0 plan, "File header").
	 */
	static final String LICENSE_HEADER = """
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
			""";

	/**
	 * The exported (API) packages: the adapter's single package.
	 */
	static final Set<String> EXPORTED_PACKAGES = Set.of(AdapterContract.ADAPTER_PACKAGE);

	/**
	 * Directory names skipped when the repository file list comes from a directory walk (no git listing): VCS
	 * metadata, build output, and local tool caches that are never committed.
	 */
	private static final Set<String> SKIPPED_DIRECTORY_NAMES = Set.of(
			".git", "target", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".gradle",
			".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox");

	private ContractSupport() {
		// Non-instantiable
	}

	/**
	 * Source text after {@link #translateUnicodeEscapes(String)}, with the offsets at which the source wrote a line
	 * terminator as a Unicode escape ({@code \}{@code u000a} or {@code \}{@code u000d}). Such a terminator is a space
	 * in the text, so line numbers keep counting the file's physical lines, and is recorded out of band, so no
	 * character the source writes (not even U+FFFF) can be mistaken for one.
	 */
	static final class TranslatedSource {
		private final String text;
		private final BitSet escapedLineTerminators;

		private TranslatedSource(String text, BitSet escapedLineTerminators) {
			this.text = text;
			this.escapedLineTerminators = (BitSet) escapedLineTerminators.clone();
		}

		String getText() {
			return this.text;
		}

		/**
		 * Returns whether the character at {@code offset} of {@link #getText()} stands for an escaped line terminator.
		 */
		boolean isEscapedLineTerminator(int offset) {
			return offset >= 0 && this.escapedLineTerminators.get(offset);
		}
	}

	/**
	 * Result of attributing a source tree with javac. Valid only inside {@link #analyze(Path, Path, Function)}.
	 */
	static final class SourceAnalysis {
		private final DocTrees trees;
		private final Elements elements;
		private final Types types;
		private final List<CompilationUnitTree> compilationUnits;
		private final Path sourceRoot;

		private SourceAnalysis(DocTrees trees, Elements elements, Types types,
				List<CompilationUnitTree> compilationUnits, Path sourceRoot) {
			this.trees = trees;
			this.elements = elements;
			this.types = types;
			this.compilationUnits = List.copyOf(compilationUnits);
			this.sourceRoot = sourceRoot;
		}

		DocTrees getTrees() {
			return this.trees;
		}

		Elements getElements() {
			return this.elements;
		}

		Types getTypes() {
			return this.types;
		}

		/**
		 * The compilation units under the analyzed source root. Stub sources resolved from the stub root are not
		 * among them.
		 */
		List<CompilationUnitTree> getCompilationUnits() {
			return this.compilationUnits;
		}

		/**
		 * Returns whether {@code type} is declared in one of the analyzed compilation units (not in the JDK, a
		 * class-path JAR or a stub source).
		 */
		boolean isAnalyzed(TypeElement type) {
			@Nullable TreePath path = this.trees.getPath(type);
			return path != null && this.compilationUnits.contains(path.getCompilationUnit());
		}

		/**
		 * Returns whether {@code subtype} is {@code supertype} or a subtype of it, ignoring type arguments.
		 */
		boolean isSubtype(TypeElement subtype, TypeElement supertype) {
			return this.types.isSubtype(this.types.erasure(subtype.asType()), this.types.erasure(supertype.asType()));
		}

		/**
		 * The source file of {@code compilationUnit} relative to the analyzed source root, with {@code /}.
		 */
		String relativePath(CompilationUnitTree compilationUnit) {
			return ContractSupport.relativePath(this.sourceRoot, Path.of(compilationUnit.getSourceFile().toUri()));
		}

		/**
		 * The physical line of a source offset in {@code compilationUnit}, or 0 if the position is unknown.
		 */
		int lineNumber(CompilationUnitTree compilationUnit, long position) {
			return position < 0 ? 0 : (int) compilationUnit.getLineMap().getLineNumber(position);
		}

		/**
		 * Returns whether {@code element} is written in the source, as opposed to generated by javac (default
		 * constructors, enum {@code values()}/{@code valueOf}, record members). Generated members have no tree or
		 * no end position; {@code Elements.getOrigin} alone does not flag all of them on JDK 17.
		 */
		boolean isSourceAuthored(Element element) {
			if (this.elements.getOrigin(element) != Elements.Origin.EXPLICIT)
				return false;
			@Nullable TreePath path = this.trees.getPath(element);
			if (path == null)
				return false;
			return this.trees.getSourcePositions().getEndPosition(path.getCompilationUnit(), path.getLeaf()) > 0;
		}

		String location(CompilationUnitTree compilationUnit, Tree tree) {
			long position = this.trees.getSourcePositions().getStartPosition(compilationUnit, tree);
			return relativePath(compilationUnit) + ":" + lineNumber(compilationUnit, position);
		}

		/**
		 * A stable, annotation-free rendering of a member for messages: {@code name(erased parameter types)} for
		 * methods and constructors (constructors use the class's simple name), the simple name otherwise. javac's own
		 * {@code Element.toString()} renders type-annotated parameters differently across JDKs.
		 */
		String describe(Element member) {
			if (!(member instanceof ExecutableElement executable))
				return member.getSimpleName().toString();
			@Nullable Element enclosingElement = executable.getEnclosingElement();
			String name = executable.getKind() == ElementKind.CONSTRUCTOR && enclosingElement != null
					? enclosingElement.getSimpleName().toString()
					: executable.getSimpleName().toString();
			return name + executable.getParameters().stream()
					.map(parameter -> erasedName(parameter.asType()))
					.collect(Collectors.joining(",", "(", ")"));
		}

		/**
		 * The erasure of {@code type} as a qualified name without annotations, such as {@code java.util.List} or
		 * {@code int[]}.
		 */
		String erasedName(TypeMirror type) {
			TypeMirror erasure = this.types.erasure(type);
			if (erasure instanceof ArrayType arrayType)
				return erasedName(arrayType.getComponentType()) + "[]";
			if (erasure instanceof DeclaredType declaredType && declaredType.asElement() instanceof TypeElement element)
				return element.getQualifiedName().toString();
			if (erasure.getKind().isPrimitive())
				return erasure.getKind().name().toLowerCase(Locale.ROOT);
			return erasure.toString();
		}
	}

	/**
	 * Finds the repository root by walking up from the working directory. Maven runs tests from the module root,
	 * but a tooling module that reuses these sources could run them from a subdirectory.
	 */
	static Path repositoryRoot() {
		Path start = Path.of("").toAbsolutePath().normalize();
		String packageInfo = "src/main/java/" + AdapterContract.adapterPackagePath() + "/package-info.java";
		for (Path candidate = start; candidate != null; candidate = candidate.getParent())
			if (Files.isRegularFile(candidate.resolve("pom.xml")) && Files.isRegularFile(candidate.resolve(packageInfo)))
				return candidate;
		throw new IllegalStateException("Unable to locate the " + AdapterContract.PRODUCT_NAME
				+ " repository root from " + start);
	}

	static void assertNoViolations(String title, List<String> violations) {
		Assertions.assertTrue(violations.isEmpty(), () -> title + " (" + violations.size() + "):\n - "
				+ String.join("\n - ", violations));
	}

	@CheckReturnValue
	static List<Path> javaSources(Path sourceRoot) throws IOException {
		if (!Files.isDirectory(sourceRoot))
			return List.of();
		try (Stream<Path> paths = Files.walk(sourceRoot)) {
			return paths.filter(Files::isRegularFile)
					.filter(path -> fileName(path).endsWith(".java"))
					.sorted()
					.toList();
		}
	}

	/**
	 * Lists the repository's regular files, sorted by relative path. When {@code root} is a git work tree and git is
	 * available, the list is exactly what git tracks or would track (tracked files, plus untracked files that
	 * {@code .gitignore} does not exclude), so a directory named {@code target} or {@code node_modules} deep in the
	 * tree is scanned unless git ignores it. Otherwise the whole tree is walked, skipping the directories named in
	 * {@link #SKIPPED_DIRECTORY_NAMES}.
	 */
	@CheckReturnValue
	static List<Path> repositoryFiles(Path root) throws IOException {
		Comparator<Path> byRelativePath = Comparator.comparing(file -> relativePath(root, file));
		Optional<Set<Path>> gitVisibleFiles = gitVisibleFiles(root);
		if (gitVisibleFiles.isPresent())
			return gitVisibleFiles.get().stream()
					.filter(file -> Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
					.sorted(byRelativePath)
					.toList();

		List<Path> files = new ArrayList<>();
		Files.walkFileTree(root, new SimpleFileVisitor<>() {
			@Override
			public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) {
				if (!directory.equals(root) && SKIPPED_DIRECTORY_NAMES.contains(fileName(directory)))
					return FileVisitResult.SKIP_SUBTREE;
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
				if (attributes.isRegularFile())
					files.add(file);
				return FileVisitResult.CONTINUE;
			}
		});
		files.sort(byRelativePath);
		return List.copyOf(files);
	}

	private static Optional<Set<Path>> gitVisibleFiles(Path root) {
		if (!Files.exists(root.resolve(".git")))
			return Optional.empty();
		try {
			Process process = new ProcessBuilder("git", "-C", root.toString(), "ls-files", "-z", "--cached", "--others",
					"--exclude-standard")
					.redirectError(ProcessBuilder.Redirect.DISCARD)
					.start();
			byte[] output;
			try (InputStream inputStream = process.getInputStream()) {
				output = readAll(inputStream);
			}
			if (!process.waitFor(60, TimeUnit.SECONDS)) {
				process.destroyForcibly();
				return Optional.empty();
			}
			if (process.exitValue() != 0)
				return Optional.empty();
			Set<Path> visible = new HashSet<>();
			String listing = new String(output, StandardCharsets.UTF_8);
			int start = 0;
			for (int index = 0; index < listing.length(); ++index) {
				if (listing.charAt(index) == '\0') {
					if (index > start)
						visible.add(root.resolve(listing.substring(start, index)).normalize());
					start = index + 1;
				}
			}
			return Optional.of(visible);
		} catch (IOException e) {
			// git is not installed; fall back to the directory walk alone.
			return Optional.empty();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return Optional.empty();
		}
	}

	private static byte[] readAll(InputStream inputStream) throws IOException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		inputStream.transferTo(outputStream);
		return outputStream.toByteArray();
	}

	static String relativePath(Path root, Path file) {
		return root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize()).toString()
				.replace(File.separatorChar, '/');
	}

	static String fileName(Path path) {
		Path fileName = path.getFileName();
		return fileName == null ? "" : fileName.toString();
	}

	/**
	 * Heuristic: a file is text if it has no NUL byte in its first 8 KiB.
	 */
	static boolean isProbablyText(byte[] bytes) {
		int limit = Math.min(bytes.length, 8192);
		for (int index = 0; index < limit; ++index)
			if (bytes[index] == 0)
				return false;
		return true;
	}

	static int lineNumber(String content, int offset) {
		int line = 1;
		for (int index = 0; index < offset && index < content.length(); ++index)
			if (content.charAt(index) == '\n')
				++line;
		return line;
	}

	/**
	 * Translates the Unicode escapes in {@code source} the way javac does before it lexes (JLS 3.3): a backslash
	 * preceded by an even number of backslashes, then one or more {@code u} and four hex digits, becomes that
	 * character. Pattern scans then see what the compiler sees, even when a keyword or name is spelled with escapes.
	 * An escaped line terminator becomes a space, never a real line terminator, so line numbers still count the file's
	 * physical lines; {@link TranslatedSource#isEscapedLineTerminator(int)} records where it stood.
	 */
	static TranslatedSource translateUnicodeEscapes(String source) {
		StringBuilder translated = new StringBuilder(source.length());
		BitSet escapedLineTerminators = new BitSet();
		int length = source.length();
		int precedingBackslashes = 0;
		int index = 0;

		while (index < length) {
			char c = source.charAt(index);
			if (c == '\\' && precedingBackslashes % 2 == 0 && index + 1 < length && source.charAt(index + 1) == 'u') {
				int digits = index + 1;
				while (digits < length && source.charAt(digits) == 'u')
					++digits;
				if (digits + 4 <= length && isHexDigits(source, digits, digits + 4)) {
					char value = (char) Integer.parseInt(source.substring(digits, digits + 4), 16);
					if (value == '\n' || value == '\r') {
						escapedLineTerminators.set(translated.length());
						translated.append(' ');
					} else {
						translated.append(value);
					}
					// A backslash produced by an escape never starts another escape (JLS 3.3).
					precedingBackslashes = value == '\\' ? 1 : 0;
					index = digits + 4;
					continue;
				}
			}
			precedingBackslashes = c == '\\' ? precedingBackslashes + 1 : 0;
			translated.append(c);
			++index;
		}

		return new TranslatedSource(translated.toString(), escapedLineTerminators);
	}

	private static boolean isHexDigits(String text, int start, int end) {
		for (int index = start; index < end; ++index)
			if (Character.digit(text.charAt(index), 16) < 0)
				return false;
		return true;
	}

	private static boolean isLineTerminator(TranslatedSource translatedSource, int index) {
		char c = translatedSource.getText().charAt(index);
		return c == '\n' || c == '\r' || translatedSource.isEscapedLineTerminator(index);
	}

	/**
	 * Replaces comments, string literals, character literals and text blocks with neutral placeholders while
	 * preserving line structure, so pattern scans see only live code. An escaped line terminator ends a line comment
	 * or literal, as in javac, and stays a space.
	 */
	static String stripCommentsAndStrings(TranslatedSource translatedSource) {
		return stripCommentsAndStrings(translatedSource, offset -> {
		});
	}

	/**
	 * {@link #stripCommentsAndStrings(TranslatedSource)} that also passes the offset of each line comment's first
	 * {@code /} (in live code, not inside another comment or a literal) to {@code lineCommentStarts}.
	 */
	static String stripCommentsAndStrings(TranslatedSource translatedSource, IntConsumer lineCommentStarts) {
		String source = translatedSource.getText();
		StringBuilder stripped = new StringBuilder(source.length());
		int length = source.length();
		int index = 0;

		while (index < length) {
			char c = source.charAt(index);
			char next = index + 1 < length ? source.charAt(index + 1) : '\0';

			if (c == '/' && next == '*') {
				index += 2;
				while (index < length && !(source.charAt(index) == '*' && index + 1 < length
						&& source.charAt(index + 1) == '/')) {
					if (source.charAt(index) == '\n')
						stripped.append('\n');
					++index;
				}
				index = Math.min(length, index + 2);
				stripped.append(' ');
			} else if (c == '/' && next == '/') {
				lineCommentStarts.accept(index);
				while (index < length && !isLineTerminator(translatedSource, index))
					++index;
			} else if (source.startsWith("\"\"\"", index)) {
				index += 3;
				while (index < length && !source.startsWith("\"\"\"", index)) {
					char textBlockCharacter = source.charAt(index);
					if (textBlockCharacter == '\\' && index + 1 < length) {
						if (source.charAt(index + 1) == '\n')
							stripped.append('\n');
						index += 2;
						continue;
					}
					if (textBlockCharacter == '\n')
						stripped.append('\n');
					++index;
				}
				index = Math.min(length, index + 3);
				stripped.append("\"\"");
			} else if (c == '"' || c == '\'') {
				char quote = c;
				++index;
				while (index < length && source.charAt(index) != quote && !isLineTerminator(translatedSource, index)) {
					if (source.charAt(index) == '\\')
						++index;
					++index;
				}
				if (index < length && source.charAt(index) == quote)
					++index;
				stripped.append(quote).append(quote);
			} else {
				stripped.append(c);
				++index;
			}
		}

		return stripped.toString();
	}

	/**
	 * Returns a copy of {@code source} of the same length in which everything except the text of documentation
	 * comments is replaced by spaces (newlines are kept). Documentation comments are {@code /** ... *}{@code /}
	 * comments, with each line's leading {@code *} decoration blanked too, and Markdown documentation comments: lines
	 * whose first non-blank characters are {@code ///} (JDK 23+ javadoc renders them even for {@code --release 17}),
	 * with the {@code ///} prefix blanked. Offsets and line numbers in the result match {@code source}.
	 */
	static String javadocText(String source) {
		char[] masked = new char[source.length()];
		for (int index = 0; index < masked.length; ++index)
			masked[index] = source.charAt(index) == '\n' ? '\n' : ' ';

		int length = source.length();
		int index = 0;
		while (index < length) {
			char c = source.charAt(index);
			char next = index + 1 < length ? source.charAt(index + 1) : '\0';

			if (c == '/' && next == '*') {
				boolean javadoc = index + 2 < length && source.charAt(index + 2) == '*'
						&& !(index + 3 < length && source.charAt(index + 3) == '/');
				int end = source.indexOf("*/", index + 2);
				if (end < 0)
					end = length;
				if (javadoc) {
					boolean atLineStart = false;
					for (int position = index + 3; position < end; ++position) {
						char commentCharacter = source.charAt(position);
						if (commentCharacter == '\n') {
							atLineStart = true;
							continue;
						}
						if (atLineStart && (commentCharacter == ' ' || commentCharacter == '\t'))
							continue;
						if (atLineStart && commentCharacter == '*')
							continue;
						atLineStart = false;
						masked[position] = commentCharacter;
					}
				}
				index = Math.min(length, end + 2);
			} else if (c == '/' && next == '/') {
				boolean markdownDoc = source.startsWith("///", index) && onlyBlanksBefore(source, index);
				int start = index + 3;
				while (index < length && source.charAt(index) != '\n')
					++index;
				if (markdownDoc)
					for (int position = start; position < index; ++position)
						masked[position] = source.charAt(position);
			} else if (source.startsWith("\"\"\"", index)) {
				int end = source.indexOf("\"\"\"", index + 3);
				while (end > 0 && source.charAt(end - 1) == '\\')
					end = source.indexOf("\"\"\"", end + 1);
				index = end < 0 ? length : end + 3;
			} else if (c == '"' || c == '\'') {
				char quote = c;
				++index;
				while (index < length && source.charAt(index) != quote && source.charAt(index) != '\n') {
					if (source.charAt(index) == '\\')
						++index;
					++index;
				}
				++index;
			} else {
				++index;
			}
		}

		return new String(masked);
	}

	/**
	 * Returns whether only spaces and tabs precede {@code index} on its line.
	 */
	private static boolean onlyBlanksBefore(String source, int index) {
		for (int position = index - 1; position >= 0 && source.charAt(position) != '\n'; --position)
			if (source.charAt(position) != ' ' && source.charAt(position) != '\t')
				return false;
		return true;
	}

	/**
	 * Parses and attributes every Java file under {@code sourceRoot} with javac ({@code --release 17}, no annotation
	 * processing) and applies {@code function} to the result. Compilation errors fail the calling test.
	 * <p>
	 * The class path holds the provided-scope JARs only: the annotations, Revetsec core and the framework API. When
	 * {@code stubRoot} is not {@code null} it becomes javac's source path, so fixture trees can stand in for core
	 * types that do not exist yet; stub sources are attributed on demand but are not analyzed compilation units.
	 */
	static <T> T analyze(Path sourceRoot, @Nullable Path stubRoot, Function<SourceAnalysis, T> function)
			throws IOException {
		List<Path> sources = javaSources(sourceRoot);
		if (sources.isEmpty())
			throw new IllegalArgumentException("No Java sources under " + sourceRoot);

		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		Assertions.assertNotNull(compiler, "Contract tests require a full JDK (javax.tools.JavaCompiler)");
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();

		List<String> options = new ArrayList<>(List.of("--release", "17", "-proc:none", "-implicit:none",
				"-Xlint:none", "-classpath", analysisClasspath()));
		if (stubRoot != null)
			options.addAll(List.of("-sourcepath", stubRoot.toString()));

		try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, Locale.ROOT,
				StandardCharsets.UTF_8)) {
			JavacTask task = (JavacTask) compiler.getTask(null, fileManager, diagnostics, options, null,
					fileManager.getJavaFileObjectsFromPaths(sources));
			List<CompilationUnitTree> compilationUnits = new ArrayList<>();
			task.parse().forEach(compilationUnits::add);
			task.analyze();

			List<String> errors = diagnostics.getDiagnostics().stream()
					.filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
					.map(diagnostic -> diagnostic.toString())
					.toList();
			Assertions.assertTrue(errors.isEmpty(), () -> "Unable to analyze sources under " + sourceRoot + ":\n"
					+ String.join("\n", errors));

			return function.apply(new SourceAnalysis(DocTrees.instance(task), task.getElements(), task.getTypes(),
					compilationUnits, sourceRoot));
		}
	}

	/**
	 * Exported types: every public top-level type in an exported package, plus every public or protected type
	 * nested in one, recursively. These are the types a caller outside the adapter can name.
	 */
	static List<TypeElement> exportedTypes(SourceAnalysis analysis) {
		List<TypeElement> exportedTypes = new ArrayList<>();
		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits()) {
			if (!EXPORTED_PACKAGES.contains(packageName(compilationUnit)))
				continue;
			for (Tree declaration : compilationUnit.getTypeDecls()) {
				Element element = analysis.getTrees().getElement(TreePath.getPath(compilationUnit, declaration));
				if (element instanceof TypeElement type && type.getModifiers().contains(Modifier.PUBLIC))
					appendExportedType(type, exportedTypes);
			}
		}
		exportedTypes.sort(Comparator.comparing(type -> analysis.getElements().getBinaryName(type).toString()));
		return List.copyOf(exportedTypes);
	}

	private static void appendExportedType(TypeElement type, List<TypeElement> exportedTypes) {
		exportedTypes.add(type);
		for (Element enclosed : type.getEnclosedElements())
			if (enclosed instanceof TypeElement nestedType && isPublicOrProtected(nestedType))
				appendExportedType(nestedType, exportedTypes);
	}

	static boolean isPublicOrProtected(Element element) {
		Set<Modifier> modifiers = element.getModifiers();
		return modifiers.contains(Modifier.PUBLIC) || modifiers.contains(Modifier.PROTECTED);
	}

	static String packageName(CompilationUnitTree compilationUnit) {
		@Nullable Tree packageName = compilationUnit.getPackageName();
		return packageName == null ? "" : packageName.toString();
	}

	/**
	 * Class path for attributing adapter sources: the JARs that hold the JSpecify, jsr305 and Error Prone
	 * annotations, plus those of {@link AdapterContract#DEPENDENCY_ANCHOR_CLASSES} (Revetsec core and the framework
	 * API). Each is located from a class it contains, so this works under any Surefire class-path mode.
	 */
	private static String analysisClasspath() {
		Stream<Class<?>> annotationClasses = Stream.of(NullMarked.class, ThreadSafe.class, CheckReturnValue.class);
		Stream<Class<?>> dependencyClasses = AdapterContract.DEPENDENCY_ANCHOR_CLASSES.stream()
				.map(ContractSupport::loadAnchorClass);
		return Stream.concat(annotationClasses, dependencyClasses)
				.map(ContractSupport::codeSourcePath)
				.distinct()
				.collect(Collectors.joining(File.pathSeparator));
	}

	private static Class<?> loadAnchorClass(String binaryName) {
		try {
			return Class.forName(binaryName, false, ContractSupport.class.getClassLoader());
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException("Unable to find " + binaryName + " on the test class path; it locates a "
					+ "provided dependency for the contract tests", e);
		}
	}

	private static String codeSourcePath(Class<?> type) {
		CodeSource codeSource = type.getProtectionDomain().getCodeSource();
		@Nullable URL location = codeSource == null ? null : codeSource.getLocation();
		if (location == null)
			throw new IllegalStateException("Unable to locate the JAR for " + type.getName());
		try {
			return Path.of(location.toURI()).toString();
		} catch (URISyntaxException e) {
			throw new IllegalStateException("Unable to locate the JAR for " + type.getName(), e);
		}
	}
}
