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
import com.sun.source.doctree.DocCommentTree;
import com.sun.source.doctree.DocTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreePath;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.TypeParameterElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.IntersectionType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.type.TypeVariable;
import javax.lang.model.type.WildcardType;
import javax.lang.model.util.ElementFilter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Source-inventory contracts for the adapter's exported API (plan R1, R2, R17, R20, 14.6), adapted from Revetsec
 * core's, which were adapted from Soklet's.
 * <p>
 * For every exported type (public top-level types in the adapter package, and their public or protected nested
 * types):
 * <ul>
 *   <li>it is not a record;</li>
 *   <li>it carries exactly one jsr305 thread-safety marker ({@code @ThreadSafe}, {@code @NotThreadSafe} or
 *   {@code @Immutable}), enums, interfaces and annotation types included;</li>
 *   <li>a concrete class is final, or sealed with every permitted subclass final or sealed in turn, unless it is in
 *   {@link #R1_EXCEPTIONS}; and it has no public or protected constructor, listed or not (R1);</li>
 *   <li>it has Javadoc with {@code @since}, and so does every public or protected member it declares or inherits
 *   from a non-exported adapter class (such as a package-private base class), since callers can reach those
 *   members too. Two exemptions: {@code @Override} methods inherit their documentation, and enum constants need
 *   Javadoc but take their {@code @since} from the enum (Pyranid precedent);</li>
 *   <li>it has no implicit public or protected constructor (declare constructors explicitly);</li>
 *   <li>no public or protected static method is named {@code of*}, {@code create*} or {@code new*} (R1);</li>
 *   <li>every non-primitive type in a public or protected field, parameter or return type carries exactly one
 *   JSpecify nullness annotation, in type-argument, array-component and wildcard-bound positions too
 *   ({@code Optional}'s type argument must be {@code @NonNull}).</li>
 * </ul>
 * No public static method of an accessible adapter type, declared or inherited, returns a type that mentions one of
 * Revetsec core's verified identity types (R17), as a subtype, a type argument or a type-variable bound included:
 * only core's validators create them, and an adapter only passes raw input to core.
 * <p>
 * Entries in {@link #R1_EXCEPTIONS} are binary names ({@code Outer$Nested}), the form every violation message
 * prints. An entry that names no exported type is reported as stale or misspelled.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class PublicApiContractTests {
	/**
	 * Revetsec core's verified identity types (plan R17, INV-G5). They exist only after every check passed, so they
	 * are created only by core's validators.
	 */
	static final Set<String> VERIFIED_TYPES = Set.of(
			"com.revetsec.jose.Jwt",
			"com.revetsec.oauth.VerifiedAccessToken",
			"com.revetsec.oidc.IdToken",
			"com.revetsec.oidc.OidcAuthentication",
			"com.revetsec.saml.SamlAuthentication",
			"com.revetsec.scim.ScimPatchResult");

	/**
	 * Binary names of the exported concrete classes approved to be neither final nor sealed (R1). The exemption covers
	 * finality only: a listed class still may not have a public or protected constructor. Each entry is a reviewed
	 * decision; there are none.
	 */
	static final Set<String> R1_EXCEPTIONS = Set.of();

	private static final Set<String> THREAD_SAFETY_MARKERS = Set.of(
			"javax.annotation.concurrent.ThreadSafe",
			"javax.annotation.concurrent.NotThreadSafe",
			"javax.annotation.concurrent.Immutable");
	private static final String NON_NULL = "org.jspecify.annotations.NonNull";
	private static final String NULLABLE = "org.jspecify.annotations.Nullable";
	private static final String OVERRIDE = "java.lang.Override";
	private static final Pattern FORBIDDEN_FACTORY_NAME = Pattern.compile("(?:of|create|new)(?:\\p{Lu}.*)?");

	@Test
	void exportedApiMeetsSourceContracts() throws IOException {
		ContractSupport.assertNoViolations("Public API contract violations",
				findViolations(ContractSupport.repositoryRoot().resolve("src/main/java"), null));
	}

	/**
	 * Checks the Java sources under {@code sourceRoot} and returns one message per violation (empty if none).
	 * {@code stubRoot}, if not {@code null}, holds stand-ins for Revetsec core types (see
	 * {@link ContractSupport#analyze(Path, Path, java.util.function.Function)}).
	 */
	static List<String> findViolations(Path sourceRoot, @Nullable Path stubRoot) throws IOException {
		return findViolations(sourceRoot, stubRoot, R1_EXCEPTIONS);
	}

	/**
	 * {@link #findViolations(Path, Path)} with the given list in place of {@link #R1_EXCEPTIONS}, so
	 * {@link ContractMetaTests} can exercise entries against the fixtures.
	 */
	static List<String> findViolations(Path sourceRoot, @Nullable Path stubRoot, Set<String> r1Exceptions)
			throws IOException {
		if (ContractSupport.javaSources(sourceRoot).isEmpty())
			return List.of();
		return ContractSupport.analyze(sourceRoot, stubRoot, analysis -> findViolations(analysis, r1Exceptions));
	}

	private static List<String> findViolations(SourceAnalysis analysis, Set<String> r1Exceptions) {
		List<String> violations = new ArrayList<>();
		List<TypeElement> exportedTypes = ContractSupport.exportedTypes(analysis);
		Set<TypeElement> exported = new HashSet<>(exportedTypes);
		for (TypeElement type : exportedTypes)
			checkExportedType(type, exported, r1Exceptions, analysis, violations);
		checkVerifiedTypes(analysis, violations);
		checkReviewedEntries("R1_EXCEPTIONS", r1Exceptions, exported, "exported type", analysis, violations);
		violations.sort(null);
		return List.copyOf(violations);
	}

	/**
	 * Every entry in a reviewed-exception list must be the binary name of a type its rule examines. Anything else,
	 * such as a canonical {@code Outer.Nested} spelling or a name left behind by a rename, exempts nothing.
	 */
	private static void checkReviewedEntries(String listName, Set<String> entries, Set<TypeElement> examinedTypes,
			String typeDescription, SourceAnalysis analysis, List<String> violations) {
		Set<String> binaryNames = examinedTypes.stream()
				.map(type -> analysis.getElements().getBinaryName(type).toString())
				.collect(Collectors.toUnmodifiableSet());
		for (String entry : entries)
			if (!binaryNames.contains(entry))
				violations.add("PublicApiContractTests." + listName + " entry \"" + entry + "\": stale or misspelled "
						+ "entry; use the binary name (Outer$Nested, as violation messages print it) of an "
						+ typeDescription + " in the analyzed sources");
	}

	private static void checkExportedType(TypeElement type, Set<TypeElement> exported, Set<String> r1Exceptions,
			SourceAnalysis analysis, List<String> violations) {
		String typeName = analysis.getElements().getBinaryName(type).toString();

		if (type.getKind() == ElementKind.RECORD)
			violations.add(typeName + ": exported types must not be records; use a final class with getX() "
					+ "accessors (R1)");

		List<String> markers = type.getAnnotationMirrors().stream()
				.map(annotation -> annotation.getAnnotationType().toString())
				.filter(THREAD_SAFETY_MARKERS::contains)
				.sorted()
				.toList();
		if (markers.size() != 1)
			violations.add(typeName + ": must declare exactly one jsr305 thread-safety marker "
					+ "(@ThreadSafe, @NotThreadSafe or @Immutable); found " + markers);

		checkDocumentation(typeName + " (type)", type, true, analysis, violations);

		boolean concreteClass = type.getKind() == ElementKind.CLASS && !type.getModifiers().contains(Modifier.ABSTRACT);
		if (concreteClass && !r1Exceptions.contains(typeName))
			checkFinal(type, typeName, analysis, violations);

		for (Element enclosed : type.getEnclosedElements()) {
			if (enclosed instanceof TypeElement || enclosed.getKind() == ElementKind.RECORD_COMPONENT
					|| !ContractSupport.isPublicOrProtected(enclosed))
				continue;

			String memberName = typeName + "#" + analysis.describe(enclosed);
			boolean explicit = analysis.isSourceAuthored(enclosed);

			if (enclosed.getKind() == ElementKind.CONSTRUCTOR && !explicit) {
				violations.add(memberName + ": implicit public or protected constructor; declare every "
						+ "constructor explicitly (R1: public concrete types have private constructors)");
				continue;
			}
			if (!explicit)
				continue;
			if (enclosed.getKind() == ElementKind.CONSTRUCTOR && concreteClass)
				violations.add(memberName + ": public concrete types have private constructors (R1)");

			checkMember(memberName, enclosed, analysis, violations);
		}

		// Members inherited from non-exported adapter classes (a package-private base class, say) are callable
		// through this type but are checked nowhere else.
		for (Element member : analysis.getElements().getAllMembers(type)) {
			if (member instanceof TypeElement || !ContractSupport.isPublicOrProtected(member)
					|| !(member.getEnclosingElement() instanceof TypeElement declaringType)
					|| declaringType.equals(type) || exported.contains(declaringType)
					|| !analysis.isAnalyzed(declaringType) || !analysis.isSourceAuthored(member))
				continue;
			checkMember(typeName + "#" + analysis.describe(member) + " (inherited from "
					+ analysis.getElements().getBinaryName(declaringType) + ")", member, analysis, violations);
		}
	}

	/**
	 * R1 finality: a concrete exported class is final, or sealed with every permitted subclass final or sealed in
	 * turn (a concrete exception with a subclass, say), so the hierarchy stays closed. A non-sealed subclass anywhere
	 * below reopens it.
	 */
	private static void checkFinal(TypeElement type, String typeName, SourceAnalysis analysis,
			List<String> violations) {
		Set<Modifier> modifiers = type.getModifiers();
		if (modifiers.contains(Modifier.FINAL))
			return;
		if (!modifiers.contains(Modifier.SEALED)) {
			violations.add(typeName + ": public concrete types are final, or sealed with only final or sealed "
					+ "permitted subclasses (R1)");
			return;
		}
		List<TypeElement> openSubclasses = new ArrayList<>();
		collectNonSealedSubclasses(type, analysis, openSubclasses, new HashSet<>());
		for (TypeElement openSubclass : openSubclasses)
			violations.add(typeName + ": sealed public concrete type permits the non-sealed subclass "
					+ analysis.getElements().getBinaryName(openSubclass) + "; every permitted subclass must be final or "
					+ "sealed (R1)");
	}

	private static void collectNonSealedSubclasses(TypeElement type, SourceAnalysis analysis,
			List<TypeElement> openSubclasses, Set<TypeElement> visited) {
		for (TypeMirror permitted : type.getPermittedSubclasses()) {
			if (!(analysis.getTypes().asElement(permitted) instanceof TypeElement permittedType)
					|| !visited.add(permittedType))
				continue;
			Set<Modifier> modifiers = permittedType.getModifiers();
			if (modifiers.contains(Modifier.SEALED))
				collectNonSealedSubclasses(permittedType, analysis, openSubclasses, visited);
			else if (!modifiers.contains(Modifier.FINAL))
				openSubclasses.add(permittedType);
		}
	}

	/**
	 * The per-member checks: documentation, nullness and factory names.
	 */
	private static void checkMember(String memberName, Element member, SourceAnalysis analysis,
			List<String> violations) {
		if (!isOverride(member))
			checkDocumentation(memberName, member, member.getKind() != ElementKind.ENUM_CONSTANT, analysis, violations);

		if (member.getKind() == ElementKind.FIELD && !member.asType().getKind().isPrimitive())
			inspectNullness(memberName + " field type", member.asType(), true, false, violations);

		if (member.getKind() == ElementKind.METHOD && member.getModifiers().contains(Modifier.STATIC)
				&& FORBIDDEN_FACTORY_NAME.matcher(member.getSimpleName()).matches())
			violations.add(memberName + ": static factories are named builder(), withX(), fromX(), *Instance() or "
					+ "fromDefaults(), never of*, create* or new* (R1, NAMING_CONVENTIONS.md)");

		if (member instanceof ExecutableElement executable) {
			for (int index = 0; index < executable.getParameters().size(); ++index) {
				TypeMirror parameterType = executable.getParameters().get(index).asType();
				if (!parameterType.getKind().isPrimitive())
					inspectNullness(memberName + " parameter " + index, parameterType, true, false, violations);
			}
			TypeMirror returnType = executable.getReturnType();
			if (returnType.getKind() != TypeKind.VOID && !returnType.getKind().isPrimitive())
				inspectNullness(memberName + " return type", returnType, true, false, violations);
		}
	}

	private static void checkDocumentation(String owner, Element element, boolean requireSince,
			SourceAnalysis analysis, List<String> violations) {
		// javac 23 and later also return Markdown (///) doc comments here, and javac 17 and 21 do not.
		// SourcePolicyTests bans /// in main sources, so the build's outcome does not depend on the JDK.
		@Nullable DocCommentTree docComment = analysis.getTrees().getDocCommentTree(element);
		if (docComment == null) {
			violations.add(owner + ": missing Javadoc (R20)");
			return;
		}
		if (requireSince && docComment.getBlockTags().stream().noneMatch(tag -> tag.getKind() == DocTree.Kind.SINCE))
			violations.add(owner + ": Javadoc has no @since tag (D28)");
	}

	private static boolean isOverride(Element element) {
		return element.getAnnotationMirrors().stream()
				.anyMatch(annotation -> annotation.getAnnotationType().toString().equals(OVERRIDE));
	}

	private static void inspectNullness(String owner, TypeMirror type, boolean root, boolean requireNonNull,
			List<String> violations) {
		boolean checked = root || (type.getKind() != TypeKind.WILDCARD && !type.getKind().isPrimitive());
		if (checked && !(requireNonNull ? hasExactNullness(type, NON_NULL) : hasAnyExactNullness(type)))
			violations.add(owner + (root ? "" : " (nested)") + ": lacks "
					+ (requireNonNull ? "@NonNull" : "exactly one JSpecify @NonNull/@Nullable") + " at " + type + " (R2)");

		if (type instanceof DeclaredType declaredType) {
			boolean optional = ((TypeElement) declaredType.asElement()).getQualifiedName()
					.contentEquals("java.util.Optional");
			List<? extends TypeMirror> arguments = declaredType.getTypeArguments();
			for (int index = 0; index < arguments.size(); ++index)
				inspectNullness(owner + " type argument " + index, arguments.get(index), false, optional, violations);
		} else if (type instanceof ArrayType arrayType) {
			TypeMirror componentType = arrayType.getComponentType();
			if (!componentType.getKind().isPrimitive())
				inspectNullness(owner + " array component", componentType, false, false, violations);
		} else if (type instanceof WildcardType wildcardType) {
			@Nullable TypeMirror extendsBound = wildcardType.getExtendsBound();
			if (extendsBound != null)
				inspectNullness(owner + " wildcard upper bound", extendsBound, false, requireNonNull, violations);
			@Nullable TypeMirror superBound = wildcardType.getSuperBound();
			if (superBound != null)
				inspectNullness(owner + " wildcard lower bound", superBound, false, requireNonNull, violations);
		}
	}

	private static boolean hasAnyExactNullness(TypeMirror type) {
		return hasExactNullness(type, NON_NULL) || hasExactNullness(type, NULLABLE);
	}

	private static boolean hasExactNullness(TypeMirror type, String annotation) {
		String opposite = annotation.equals(NON_NULL) ? NULLABLE : NON_NULL;
		Set<String> annotations = type.getAnnotationMirrors().stream()
				.map(value -> value.getAnnotationType().toString())
				.collect(Collectors.toUnmodifiableSet());
		return annotations.contains(annotation) && !annotations.contains(opposite);
	}

	/**
	 * R17: verified identity types come only from core's validators. No accessible adapter type has a public static
	 * method, declared or inherited from a non-accessible adapter class, that returns one.
	 */
	private static void checkVerifiedTypes(SourceAnalysis analysis, List<String> violations) {
		List<TypeElement> verifiedTypes = VERIFIED_TYPES.stream()
				.map(name -> analysis.getElements().getTypeElement(name))
				.filter(Objects::nonNull)
				.toList();
		List<TypeElement> topLevelTypes = new ArrayList<>();
		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits())
			for (Tree declaration : compilationUnit.getTypeDecls())
				if (analysis.getTrees().getElement(TreePath.getPath(compilationUnit, declaration))
						instanceof TypeElement type)
					topLevelTypes.add(type);

		Set<TypeElement> accessibleTypes = new LinkedHashSet<>();
		for (TypeElement type : topLevelTypes)
			collectAccessibleTypes(type, type.getModifiers().contains(Modifier.PUBLIC), accessibleTypes);

		for (TypeElement type : accessibleTypes) {
			String typeName = analysis.getElements().getBinaryName(type).toString();
			for (ExecutableElement method : ElementFilter.methodsIn(analysis.getElements().getAllMembers(type))) {
				if (!method.getModifiers().contains(Modifier.PUBLIC) || !method.getModifiers().contains(Modifier.STATIC)
						|| !(method.getEnclosingElement() instanceof TypeElement declaringType))
					continue;
				boolean inherited = !declaringType.equals(type);
				if (inherited && (accessibleTypes.contains(declaringType) || !analysis.isAnalyzed(declaringType)))
					continue;
				if (mentionsVerifiedType(method.getReturnType(), verifiedTypes, analysis, new HashSet<>()))
					violations.add(typeName + "#" + analysis.describe(method) + (inherited ? " (inherited from "
							+ analysis.getElements().getBinaryName(declaringType) + ")" : "")
							+ ": public static method returns a verified type; only Revetsec core's validators may "
							+ "create one (R17)");
			}
		}
	}

	private static void collectAccessibleTypes(TypeElement type, boolean accessible, Set<TypeElement> accessibleTypes) {
		if (accessible)
			accessibleTypes.add(type);
		for (TypeElement nested : ElementFilter.typesIn(type.getEnclosedElements()))
			collectAccessibleTypes(nested, accessible && ContractSupport.isPublicOrProtected(nested), accessibleTypes);
	}

	private static boolean isVerifiedType(TypeElement type, List<TypeElement> verifiedTypes, SourceAnalysis analysis) {
		return verifiedTypes.stream().anyMatch(verifiedType -> analysis.isSubtype(type, verifiedType));
	}

	/**
	 * Returns whether {@code type} is, contains or is bounded by a verified type or a subtype of one (a nested type of
	 * a verified type counts too).
	 */
	private static boolean mentionsVerifiedType(TypeMirror type, List<TypeElement> verifiedTypes,
			SourceAnalysis analysis, Set<TypeParameterElement> visitedTypeVariables) {
		if (type instanceof DeclaredType declaredType) {
			for (@Nullable Element element = declaredType.asElement(); element instanceof TypeElement typeElement;
					element = typeElement.getEnclosingElement())
				if (isVerifiedType(typeElement, verifiedTypes, analysis))
					return true;
			return declaredType.getTypeArguments().stream().anyMatch(argument ->
					mentionsVerifiedType(argument, verifiedTypes, analysis, visitedTypeVariables));
		}
		if (type instanceof ArrayType arrayType)
			return mentionsVerifiedType(arrayType.getComponentType(), verifiedTypes, analysis, visitedTypeVariables);
		if (type instanceof WildcardType wildcardType) {
			@Nullable TypeMirror extendsBound = wildcardType.getExtendsBound();
			@Nullable TypeMirror superBound = wildcardType.getSuperBound();
			return (extendsBound != null && mentionsVerifiedType(extendsBound, verifiedTypes, analysis,
					visitedTypeVariables))
					|| (superBound != null && mentionsVerifiedType(superBound, verifiedTypes, analysis,
					visitedTypeVariables));
		}
		if (type instanceof TypeVariable typeVariable
				&& typeVariable.asElement() instanceof TypeParameterElement typeParameter
				&& visitedTypeVariables.add(typeParameter))
			return mentionsVerifiedType(typeVariable.getUpperBound(), verifiedTypes, analysis, visitedTypeVariables);
		if (type instanceof IntersectionType intersectionType)
			return intersectionType.getBounds().stream()
					.anyMatch(bound -> mentionsVerifiedType(bound, verifiedTypes, analysis, visitedTypeVariables));
		return false;
	}
}
