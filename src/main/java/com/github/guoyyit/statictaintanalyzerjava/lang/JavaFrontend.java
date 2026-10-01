package com.github.guoyyit.statictaintanalyzerjava.lang;

import com.github.guoyyit.statictaintanalyzerjava.analysis.FunctionSummary;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumConstantDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.InitializerDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.type.Type;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Java source frontend: parses one {@code .java} file with JavaParser and lowers
 * every declared type member (methods, constructors, field initializers, class
 * initializers, record sugar, enum constant bodies, anonymous classes) into
 * language-neutral {@link FunctionSummary} facts.
 *
 * <p>Failures of one file are reported as {@link JavaParseException} carrying a
 * {@link ParseFailure} with file name, line and error code; they never abort
 * analysis of the remaining files.
 */
public final class JavaFrontend {

    public List<FunctionSummary> summarizeFile(String fileName, String source) {
        ParserConfiguration configuration = new ParserConfiguration();
        configuration.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17);
        configuration.setCharacterEncoding(StandardCharsets.UTF_8);
        JavaParser parser = new JavaParser(configuration);
        ParseResult<CompilationUnit> result = parser.parse(source);
        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            List<com.github.javaparser.Problem> problems = new ArrayList<>(result.getProblems());
            com.github.javaparser.Problem lexical = problems.stream()
                    .filter(JavaFrontend::isLexical)
                    .min((a, b) -> Integer.compare(lineOf(a), lineOf(b)))
                    .orElse(null);
            com.github.javaparser.Problem firstLocated = problems.stream()
                    .filter(p -> p.getLocation().isPresent())
                    .min((a, b) -> Integer.compare(lineOf(a), lineOf(b)))
                    .orElse(null);
            ParseFailure failure;
            if (lexical != null) {
                int line = lineOf(lexical);
                failure = line > 0 ? ParseFailure.lexical(fileName, line, lexical.getMessage())
                        : ParseFailure.lexical(fileName, extractLine(lexical.getMessage()), lexical.getMessage());
            } else if (firstLocated != null) {
                failure = ParseFailure.syntax(fileName, lineOf(firstLocated), firstLocated.getMessage());
            } else {
                failure = ParseFailure.syntax(fileName, 0, "unparseable Java source");
            }
            throw new JavaParseException(failure);
        }
        try {
            return new Lowerer(fileName).lower(result.getResult().get());
        } catch (JavaParseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new JavaParseException(ParseFailure.internal(fileName, 0,
                    e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    static int lineOf(com.github.javaparser.Problem p) {
        return p.getLocation().flatMap(l -> l.getBegin().getRange())
                .map(r -> r.begin.line).orElse(0);
    }

    static int lineOf(Node node) {
        return node.getBegin().map(p -> p.line).orElse(0);
    }

    private static ParseFailure classify(String fileName, com.github.javaparser.Problem problem) {
        int line = lineOf(problem);
        if (isLexical(problem)) {
            return ParseFailure.lexical(fileName, line, problem.getMessage());
        }
        return ParseFailure.syntax(fileName, line, problem.getMessage());
    }

    private static boolean isLexical(com.github.javaparser.Problem problem) {
        String cause = problem.getCause().map(t -> t.getClass().getSimpleName()).orElse("");
        String message = problem.getMessage();
        return cause.contains("TokenMgr") || message.toLowerCase().contains("lexical")
                || message.contains("Invalid character") || message.contains("Unicode escape");
    }

    /** Recovers a 1-based line from messages like "Lexical error at line 3, column 5". */
    private static int extractLine(String message) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("line\\s+(\\d+)").matcher(message == null ? "" : message);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    /** Strips generics and array dimensions to a simple type token. */
    static String cleanType(Type type) {
        String text = type.asString();
        int gen = text.indexOf('<');
        if (gen >= 0) {
            text = text.substring(0, gen);
        }
        return text.replace("[]", "").replace("...", "").trim();
    }

    /** Per-file lowering state; one instance per parsed compilation unit. */
    private static final class Lowerer {
        private final String file;
        private final List<FunctionSummary> out = new ArrayList<>();
        private int anonymousCounter;

        private Lowerer(String file) {
            this.file = file;
        }

        List<FunctionSummary> lower(CompilationUnit cu) {
            String pkg = cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
            List<String> imports = new ArrayList<>();
            for (com.github.javaparser.ast.ImportDeclaration imp : cu.getImports()) {
                imports.add(imp.getNameAsString() + (imp.isAsterisk() ? ".*" : "")
                        + (imp.isStatic() ? ":static" : ""));
            }
            for (TypeDeclaration<?> type : cu.getTypes()) {
                lowerType(type, pkg, List.copyOf(imports), new ArrayList<>());
            }
            return List.copyOf(out);
        }

        private void lowerType(TypeDeclaration<?> type, String pkg, List<String> imports, List<String> outer) {
            List<String> chain = new ArrayList<>(outer);
            chain.add(type.getNameAsString());
            String fqn = pkg.isEmpty() ? String.join(".", chain) : pkg + "." + String.join(".", chain);

            List<String> supers = new ArrayList<>();
            if (type instanceof ClassOrInterfaceDeclaration c) {
                c.getExtendedTypes().forEach(t -> supers.add(t.getNameWithScope()));
                c.getImplementedTypes().forEach(t -> supers.add(t.getNameWithScope()));
            } else if (type instanceof EnumDeclaration e) {
                e.getImplementedTypes().forEach(t -> supers.add(t.getNameWithScope()));
            } else if (type instanceof RecordDeclaration r) {
                r.getImplementedTypes().forEach(t -> supers.add(t.getNameWithScope()));
            }
            // Emit a structural type marker even for member-less types so the
            // global index can traverse inheritance through empty classes/interfaces.
            out.add(FunctionSummary.javaTypeMarker(fqn, file, pkg, imports, List.copyOf(supers)));

            List<String> recordComponents = new ArrayList<>();
            if (type instanceof RecordDeclaration r) {
                for (var p : r.getParameters()) {
                    recordComponents.add(p.getNameAsString() + ":" + cleanType(p.getType()));
                }
            }
            boolean hasCanonicalCtor = false;
            for (BodyDeclaration<?> member : type.getMembers()) {
                if (member instanceof MethodDeclaration m && m.getBody().isPresent()) {
                    lowerMethod(fqn, m, pkg, imports, supers);
                } else if (member instanceof ConstructorDeclaration c) {
                    lowerConstructor(fqn, c, pkg, imports, supers);
                    if (type instanceof RecordDeclaration && c.getParameters().size() == recordComponents.size()) {
                        hasCanonicalCtor = true;
                    }
                } else if (member instanceof InitializerDeclaration init) {
                    MemberLowerer ml = new MemberLowerer(file, fqn, "<clinit>", pkg, imports, supers,
                            true, MemberLowerer.Kind.STATIC);
                    ml.lowerBlock(init.getBody());
                    out.add(ml.build(lineOf(init)));
                } else if (member instanceof FieldDeclaration field) {
                    lowerField(fqn, field, pkg, imports, supers);
                } else if (member instanceof TypeDeclaration<?> nested) {
                    lowerType(nested, pkg, imports, chain);
                }
            }
            if (type instanceof RecordDeclaration) {
                if (!hasCanonicalCtor) {
                    lowerRecordCanonicalCtor(fqn, recordComponents, pkg, imports, supers);
                }
                lowerRecordAccessors(fqn, recordComponents, pkg, imports, supers);
            }
            if (type instanceof EnumDeclaration e) {
                lowerEnumConstantBodies(fqn, e, pkg, imports, supers);
            }
            lowerAnonymousClasses(type, fqn, pkg, imports, supers);
        }

        private void lowerMethod(String fqn, MethodDeclaration m, String pkg,
                                 List<String> imports, List<String> supers) {
            MemberLowerer ml = new MemberLowerer(file, fqn, m.getNameAsString(), pkg, imports, supers,
                    m.isStatic(), MemberLowerer.Kind.METHOD);
            if (!m.isStatic()) {
                ml.addThisParam();
            }
            for (var p : m.getParameters()) {
                ml.addParam(p.getNameAsString(), cleanType(p.getType()));
            }
            m.getBody().ifPresent(ml::lowerBlock);
            out.add(ml.build(lineOf(m)));
        }

        private void lowerConstructor(String fqn, ConstructorDeclaration c, String pkg,
                                      List<String> imports, List<String> supers) {
            MemberLowerer ml = new MemberLowerer(file, fqn, "<init>", pkg, imports, supers,
                    false, MemberLowerer.Kind.CONSTRUCTOR);
            ml.addThisParam();
            for (var p : c.getParameters()) {
                ml.addParam(p.getNameAsString(), cleanType(p.getType()));
            }
            ml.lowerBlock(c.getBody());
            out.add(ml.build(lineOf(c)));
        }

        private void lowerField(String fqn, FieldDeclaration field, String pkg,
                                List<String> imports, List<String> supers) {
            for (VariableDeclarator declarator : field.getVariables()) {
                MemberLowerer ml = new MemberLowerer(file, fqn,
                        "field:" + declarator.getNameAsString(), pkg, imports, supers,
                        field.isStatic(), MemberLowerer.Kind.FIELD);
                declarator.getInitializer().ifPresent(value -> {
                    List<String> srcs = ml.lowerExpr(value);
                    ml.fieldWrite(declarator.getNameAsString(), List.of(fqn), srcs, lineOf(value));
                });
                out.add(ml.build(lineOf(declarator)));
            }
        }

        private void lowerRecordCanonicalCtor(String fqn, List<String> components, String pkg,
                                              List<String> imports, List<String> supers) {
            MemberLowerer ctor = new MemberLowerer(file, fqn, "<init>", pkg, imports, supers,
                    false, MemberLowerer.Kind.CONSTRUCTOR);
            ctor.addThisParam();
            for (String component : components) {
                String name = component.substring(0, component.indexOf(':'));
                ctor.addParam(name, component.substring(component.indexOf(':') + 1));
                ctor.fieldWrite(name, List.of(fqn), List.of(name), 1);
            }
            out.add(ctor.build(1));
        }

        private void lowerRecordAccessors(String fqn, List<String> components, String pkg,
                                          List<String> imports, List<String> supers) {
            for (String component : components) {
                String name = component.substring(0, component.indexOf(':'));
                MemberLowerer accessor = new MemberLowerer(file, fqn, name, pkg, imports, supers,
                        false, MemberLowerer.Kind.METHOD);
                accessor.addThisParam();
                String temp = accessor.fieldRead(name, List.of(fqn), 1);
                accessor.addReturn(List.of(temp), 1);
                out.add(accessor.build(1));
            }
        }

        private void lowerEnumConstantBodies(String fqn, EnumDeclaration e, String pkg,
                                             List<String> imports, List<String> supers) {
            for (EnumConstantDeclaration constant : e.getEntries()) {
                if (constant.getClassBody() == null || constant.getClassBody().isEmpty()) {
                    continue;
                }
                String anonFqn = fqn + "." + constant.getNameAsString();
                for (BodyDeclaration<?> member : constant.getClassBody()) {
                    if (member instanceof MethodDeclaration m && m.getBody().isPresent()) {
                        MemberLowerer ml = new MemberLowerer(file, anonFqn, m.getNameAsString(), pkg,
                                imports, List.of(fqn), m.isStatic(), MemberLowerer.Kind.METHOD);
                        if (!m.isStatic()) {
                            ml.addThisParam();
                        }
                        for (var p : m.getParameters()) {
                            ml.addParam(p.getNameAsString(), cleanType(p.getType()));
                        }
                        m.getBody().ifPresent(ml::lowerBlock);
                        out.add(ml.build(lineOf(m)));
                    }
                }
            }
        }

        private void lowerAnonymousClasses(TypeDeclaration<?> type, String fqn, String pkg,
                                           List<String> imports, List<String> supers) {
            for (ObjectCreationExpr oce : type.findAll(ObjectCreationExpr.class)) {
                Optional<TypeDeclaration<?>> nearest = oce.findAncestor(TypeDeclaration.class)
                        .map(n -> (TypeDeclaration<?>) n);
                if (nearest.isEmpty() || nearest.get() != type || oce.getAnonymousClassBody().isEmpty()) {
                    continue;
                }
                String anonFqn = fqn + "$Anonymous" + (anonymousCounter++);
                List<String> anonSupers = List.of(cleanType(oce.getType()));
                for (BodyDeclaration<?> member : oce.getAnonymousClassBody().orElseThrow()) {
                    if (member instanceof MethodDeclaration m && m.getBody().isPresent()) {
                        MemberLowerer ml = new MemberLowerer(file, anonFqn, m.getNameAsString(), pkg,
                                imports, anonSupers, m.isStatic(), MemberLowerer.Kind.METHOD);
                        if (!m.isStatic()) {
                            ml.addThisParam();
                        }
                        for (var p : m.getParameters()) {
                            ml.addParam(p.getNameAsString(), cleanType(p.getType()));
                        }
                        m.getBody().ifPresent(ml::lowerBlock);
                        out.add(ml.build(lineOf(m)));
                    } else if (member instanceof FieldDeclaration field) {
                        lowerField(anonFqn, field, pkg, imports, anonSupers);
                    }
                }
            }
        }
    }
}
