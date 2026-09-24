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
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.ImportTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreePathScanner;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.PackageElement;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Package rules for an adapter (plan 6, 7.10), adapted from RevetSec core's {@code PackageDependencyTests}.
 * <ul>
 *   <li>The adapter has exactly one package, {@link AdapterContract#ADAPTER_PACKAGE}, and it has a
 *   {@code package-info.java} annotated {@code @NullMarked}.</li>
 *   <li>The adapter uses only RevetSec core's public API: no import of, and no resolved reference to, anything in
 *   {@code com.revetsec.internal} or its subpackages. Fully qualified names and static imports count too.</li>
 * </ul>
 * Which framework the adapter may use needs no test here: the enforcer allow-list in {@code pom.xml} puts only
 * RevetSec core, this adapter's framework API and the annotation JARs on the main compile class path, so code that
 * names another framework does not compile.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class PackageDependencyTests {
	private static final String CORE_INTERNAL = "com.revetsec.internal";
	private static final String NULL_MARKED = "org.jspecify.annotations.NullMarked";

	@Test
	void mainSourcesRespectPackageRules() throws IOException {
		ContractSupport.assertNoViolations("Package rule violations",
				findViolations(ContractSupport.repositoryRoot().resolve("src/main/java"), null));
	}

	/**
	 * Checks the Java sources under {@code sourceRoot} and returns one message per violation (empty if none).
	 * {@code stubRoot}, if not {@code null}, holds stand-ins for RevetSec core types.
	 */
	static List<String> findViolations(Path sourceRoot, @Nullable Path stubRoot) throws IOException {
		if (ContractSupport.javaSources(sourceRoot).isEmpty())
			return List.of(AdapterContract.ADAPTER_PACKAGE + ": package has no sources; it needs at least a "
					+ "package-info.java (R20)");
		return ContractSupport.analyze(sourceRoot, stubRoot, PackageDependencyTests::findViolations);
	}

	private static List<String> findViolations(SourceAnalysis analysis) {
		Set<String> violations = new TreeSet<>();
		Set<String> declaredPackages = new TreeSet<>();
		Set<String> packagesWithPackageInfo = new HashSet<>();

		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits()) {
			String packageName = ContractSupport.packageName(compilationUnit);
			declaredPackages.add(packageName);
			if (ContractSupport.fileName(Path.of(compilationUnit.getSourceFile().toUri())).equals("package-info.java"))
				packagesWithPackageInfo.add(packageName);
		}
		declaredPackages.add(AdapterContract.ADAPTER_PACKAGE);

		for (String packageName : declaredPackages) {
			if (!packageName.equals(AdapterContract.ADAPTER_PACKAGE))
				violations.add(packageName + ": adapters have exactly one package, " + AdapterContract.ADAPTER_PACKAGE
						+ "; move this code there, or into RevetSec core");
			if (!packagesWithPackageInfo.contains(packageName)) {
				violations.add(packageName + ": package has no package-info.java (R20)");
			} else {
				@Nullable PackageElement packageElement = analysis.getElements().getPackageElement(packageName);
				boolean nullMarked = packageElement != null && packageElement.getAnnotationMirrors().stream()
						.anyMatch(annotation -> annotation.getAnnotationType().toString().equals(NULL_MARKED));
				if (!nullMarked)
					violations.add(packageName + ": package-info.java is not annotated @NullMarked (R2)");
			}
		}

		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits())
			findCoreInternalReferences(compilationUnit, analysis, violations);

		return List.copyOf(violations);
	}

	/**
	 * Reports each line of {@code compilationUnit} that imports or refers to anything in RevetSec core's internal
	 * packages.
	 */
	private static void findCoreInternalReferences(CompilationUnitTree compilationUnit, SourceAnalysis analysis,
			Set<String> violations) {
		new TreePathScanner<Void, Void>() {
			@Override
			public @Nullable Void visitImport(ImportTree node, Void unused) {
				String name = node.getQualifiedIdentifier().toString();
				if (name.endsWith(".*"))
					name = name.substring(0, name.length() - 2);
				if (isCoreInternal(name))
					report(node, name);
				return null;
			}

			@Override
			public @Nullable Void visitIdentifier(IdentifierTree node, Void unused) {
				recordReference(node);
				return super.visitIdentifier(node, null);
			}

			@Override
			public @Nullable Void visitMemberSelect(MemberSelectTree node, Void unused) {
				recordReference(node);
				return super.visitMemberSelect(node, null);
			}

			private void recordReference(Tree node) {
				@Nullable Element element = analysis.getTrees().getElement(getCurrentPath());
				if (element == null || element.getKind() == ElementKind.PACKAGE)
					return;
				String packageName = analysis.getElements().getPackageOf(element).getQualifiedName().toString();
				if (isCoreInternal(packageName))
					report(node, packageName);
			}

			private void report(Tree node, String target) {
				violations.add(analysis.location(compilationUnit, node) + ": uses " + target + "; adapters use only "
						+ "RevetSec core's public API, and com.revetsec.internal is not API (plan 6, 7.10)");
			}
		}.scan(compilationUnit, null);
	}

	private static boolean isCoreInternal(String name) {
		return name.equals(CORE_INTERNAL) || name.startsWith(CORE_INTERNAL + ".");
	}
}
