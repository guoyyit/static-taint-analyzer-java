package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.analysis.model.MethodModel;
import com.github.guoyyit.statictaintanalyzerjava.analysis.model.ProgramModel;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Parses {@code .java} files into a {@link ProgramModel}: methods, call edges
 * (resolved by name + arity, deterministically) and a field read/write index.
 */
public final class JavaModelBuilder {

    private final JavaParser parser = new JavaParser();

    /** Parses all {@code .java} files under {@code sourceDir} (sorted by path). */
    public ProgramModel build(Path sourceDir) {
        List<Path> files = listJavaFiles(sourceDir);
        ProgramModel model = new ProgramModel();
        for (Path file : files) {
            parseInto(model, sourceDir.relativize(file).toString(), file);
        }
        buildCallGraph(model);
        return model;
    }

    /** Parses the given in-memory sources (path -> content); used by tests and incremental runs. */
    public ProgramModel buildFromStrings(java.util.Map<String, String> sources) {
        ProgramModel model = new ProgramModel();
        sources.entrySet().stream()
                .sorted(java.util.Map.Entry.comparingByKey())
                .forEach(e -> parseContent(model, e.getKey(), e.getValue()));
        buildCallGraph(model);
        return model;
    }

    private List<Path> listJavaFiles(Path sourceDir) {
        try (Stream<Path> walk = Files.walk(sourceDir)) {
            return walk.filter(p -> p.toString().endsWith(".java"))
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void parseInto(ProgramModel model, String relativePath, Path file) {
        try {
            parseContent(model, relativePath, Files.readString(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void parseContent(ProgramModel model, String file, String content) {
        parser.parse(content).getResult().ifPresent(cu -> collect(model, file, cu));
    }

    private void collect(ProgramModel model, String file, CompilationUnit cu) {
        String pkg = cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
        for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            String className = pkg.isEmpty() ? clazz.getNameAsString()
                    : pkg + "." + clazz.getNameAsString();
            model.addClass(className);
            for (FieldDeclaration field : clazz.getFields()) {
                field.getVariables().forEach(v ->
                        model.addClassField(className, v.getNameAsString(), v.getTypeAsString()));
            }
            for (MethodDeclaration md : clazz.getMethods()) {
                List<String> paramNames = new ArrayList<>();
                List<String> paramTypes = new ArrayList<>();
                for (Parameter p : md.getParameters()) {
                    paramNames.add(p.getNameAsString());
                    paramTypes.add(p.getTypeAsString());
                }
                String signature = className + "#" + md.getNameAsString()
                        + "(" + String.join(",", paramTypes) + ")";
                model.addMethod(new MethodModel(signature, className, md.getNameAsString(),
                        List.copyOf(paramNames), List.copyOf(paramTypes), file, md));
            }
        }
    }

    private void buildCallGraph(ProgramModel model) {
        for (MethodModel method : model.methods()) {
            MethodDeclaration md = method.declaration();
            md.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodCallExpr call, Void arg) {
                    super.visit(call, arg);
                    for (MethodModel candidate : model.byName(call.getNameAsString())) {
                        if (candidate.arity() == call.getArguments().size()
                                && !candidate.signature().equals(method.signature())) {
                            model.addCallEdge(method.signature(), candidate.signature());
                        }
                    }
                }
            }, null);
            indexFieldAccesses(model, method, md);
        }
    }

    private void indexFieldAccesses(ProgramModel model, MethodModel method, MethodDeclaration md) {
        var fieldNames = model.fieldTypesOf(method.className()).keySet();
        md.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(AssignExpr assign, Void arg) {
                super.visit(assign, arg);
                fieldKey(assign.getTarget()).ifPresent(key ->
                        model.addFieldWrite(key, method.signature()));
            }

            @Override
            public void visit(UnaryExpr unary, Void arg) {
                super.visit(unary, arg);
                fieldKey(unary.getExpression()).ifPresent(key ->
                        model.addFieldWrite(key, method.signature()));
            }

            @Override
            public void visit(FieldAccessExpr access, Void arg) {
                super.visit(access, arg);
                if (!isWriteContext(access)) {
                    model.addFieldRead(method.className() + "." + access.getNameAsString(),
                            method.signature());
                }
            }

            @Override
            public void visit(NameExpr name, Void arg) {
                super.visit(name, arg);
                if (fieldNames.contains(name.getNameAsString()) && !isWriteContext(name)) {
                    model.addFieldRead(method.className() + "." + name.getNameAsString(),
                            method.signature());
                }
            }

            private java.util.Optional<String> fieldKey(Expression expr) {
                if (expr instanceof FieldAccessExpr fa) {
                    return java.util.Optional.of(method.className() + "." + fa.getNameAsString());
                }
                if (expr instanceof NameExpr ne && fieldNames.contains(ne.getNameAsString())) {
                    return java.util.Optional.of(method.className() + "." + ne.getNameAsString());
                }
                return java.util.Optional.empty();
            }

            private boolean isWriteContext(Expression expr) {
                return expr.getParentNode()
                        .filter(p -> p instanceof AssignExpr a && a.getTarget() == expr)
                        .isPresent();
            }
        }, null);
    }
}
