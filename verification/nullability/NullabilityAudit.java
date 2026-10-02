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

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.type.WildcardType;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaFileObject;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Readonly attributed signature audit for unpublished examples; writes only its requested JSON evidence.
 * <p>Arguments: newline-delimited Java source-list file, resolved classpath file, output JSON file.
 * Caller includes every main/test source and the compiled example classes plus its resolved test dependencies.
 * @since 1.0.0
 */
@NotThreadSafe
@SuppressWarnings("removal") // Java 17 source positions remain the common API for the 17–27 audit lanes.
public final class NullabilityAudit {
    private NullabilityAudit() { }

    /** Audits all source-declared methods,constructors and record components,including nested references.
     * @param arguments source-list,class-path and output paths
     * @throws IOException if evidence or source cannot be read
     * @since 1.0.0
     */
    public static void main(@NonNull String @NonNull [] arguments) throws IOException {
        if (arguments.length != 3) throw new IllegalArgumentException("Expected source-list,class-path,output");
        List<Path> sources = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(arguments[0]), StandardCharsets.UTF_8)) {
            if (!line.isBlank()) sources.add(Path.of(line).toAbsolutePath().normalize());
        }
        if (sources.isEmpty() || new HashSet<>(sources).size() != sources.size()
                || sources.stream().anyMatch(path -> !Files.isRegularFile(path) || !path.toString().endsWith(".java")))
            throw new IllegalArgumentException("Expected unique existing Java sources");
        sources.sort(Path::compareTo);
        String classpath = Files.readString(Path.of(arguments[1]), StandardCharsets.UTF_8).strip();
        if (classpath.isEmpty()) throw new IllegalArgumentException("Expected resolved classpath");
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("Run with a JDK");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        Audit audit = new Audit();
        try (var manager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            JavacTask task = (JavacTask) compiler.getTask(null, manager, diagnostics,
                    List.of("-proc:none", "--release", "17", "-classpath", classpath), null,
                    manager.getJavaFileObjectsFromPaths(sources));
            List<CompilationUnitTree> units = new ArrayList<>();
            task.parse().forEach(units::add);
            task.analyze();
            Trees trees = Trees.instance(task);
            for (CompilationUnitTree unit : units) {
                new TreePathScanner<Void, Void>() {
                    private @NonNull String label(@NonNull Tree tree, @NonNull String member) {
                        long position = trees.getSourcePositions().getStartPosition(unit, tree);
                        return unit.getSourceFile().getName() + ":" + unit.getLineMap().getLineNumber(position) + " " + member;
                    }
                    @Override public @Nullable Void visitMethod(@NonNull MethodTree method, @Nullable Void unused) {
                        if (trees.getSourcePositions().getEndPosition(unit, method) >= 0
                                && trees.getElement(getCurrentPath()) instanceof ExecutableElement executable) {
                            audit.inspect(label(method, method.getName() + " return"), executable.getReturnType());
                            for (var parameter : executable.getParameters())
                                audit.inspect(label(method, method.getName() + " parameter " + parameter.getSimpleName()), parameter.asType());
                        }
                        return super.visitMethod(method, unused);
                    }
                    @Override public @Nullable Void visitVariable(@NonNull VariableTree variable, @Nullable Void unused) {
                        if (getCurrentPath().getParentPath().getLeaf() instanceof ClassTree declaration
                                && declaration.getKind() == Tree.Kind.RECORD
                                && trees.getElement(getCurrentPath().getParentPath()) instanceof TypeElement record) {
                            for (var component : record.getRecordComponents())
                                if (component.getSimpleName().contentEquals(variable.getName()))
                                    audit.inspect(label(variable, "record component " + component.getSimpleName()), component.asType());
                        }
                        return super.visitVariable(variable, unused);
                    }
                }.scan(unit, null);
            }
        }
        boolean attributionFailed = false;
        for (var diagnostic : diagnostics.getDiagnostics()) {
            if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
                attributionFailed = true;
                audit.errors.add(diagnostic.toString());
            }
        }
        String json = "{\"source_files\":" + sources.size() + ",\"checked_reference_positions\":" + audit.checked
                + ",\"missing\":[" + String.join(",", audit.missing.stream().map(NullabilityAudit::quote).toList())
                + "],\"attribution_errors\":[" + String.join(",", audit.errors.stream().map(NullabilityAudit::quote).toList()) + "]}\n";
        Files.writeString(Path.of(arguments[2]), json, StandardCharsets.UTF_8);
        if (attributionFailed || !audit.missing.isEmpty()) System.exit(1);
    }

    private static @NonNull String quote(@NonNull String value) {
        StringBuilder output = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> { if (character < 32) output.append(String.format("\\u%04x", (int) character)); else output.append(character); }
            }
        }
        return output.append('"').toString();
    }

    private static final class Audit {
        private int checked;
        private final @NonNull List<@NonNull String> missing = new ArrayList<>();
        private final @NonNull List<@NonNull String> errors = new ArrayList<>();
        private Audit() { }

        private void inspect(@NonNull String owner, @NonNull TypeMirror type) {
            if (type.getKind().isPrimitive() || type.getKind() == TypeKind.VOID || type.getKind() == TypeKind.NONE) return;
            if (type instanceof WildcardType wildcard) {
                if (wildcard.getExtendsBound() != null) inspect(owner + " upper bound", wildcard.getExtendsBound());
                if (wildcard.getSuperBound() != null) inspect(owner + " lower bound", wildcard.getSuperBound());
                return;
            }
            this.checked++;
            Set<String> annotations = new HashSet<>();
            for (var annotation : type.getAnnotationMirrors()) annotations.add(annotation.getAnnotationType().toString());
            if (annotations.contains("org.jspecify.annotations.NonNull") == annotations.contains("org.jspecify.annotations.Nullable"))
                this.missing.add(owner + ": expected exactly one JSpecify @NonNull/@Nullable");
            if (type instanceof DeclaredType declared) {
                for (int index = 0; index < declared.getTypeArguments().size(); index++)
                    inspect(owner + " argument " + index, declared.getTypeArguments().get(index));
            } else if (type instanceof ArrayType array) inspect(owner + " component", array.getComponentType());
        }
    }
}
