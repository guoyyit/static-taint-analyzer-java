package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaAst;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lowers Java method bodies into {@link FunctionSummary} flow facts consumed by
 * the (language agnostic) taint engine.
 *
 * <p>Synthetic members are produced so field initializers and initializer
 * blocks participate in analysis: instance initializers are prepended to every
 * constructor body, a default constructor is synthesized when none exists, and
 * static initializers plus static field initializers form a synthetic
 * {@code <clinit>} whose field namespace is the shared {@code $static} scope.
 */
public final class JavaSummarizer {

    public static final String INIT = "<init>";
    public static final String CLINIT = "<clinit>";
    public static final String THIS = "$this";
    public static final String STATIC_SCOPE = "$static";

    private String file;
    private List<String> imports;
    private String ownerQ;
    private String ownerSimple;
    private boolean methodStatic;
    private boolean constructor;
    private List<String> params;
    private Map<String, String> locals;
    private final java.util.Set<String> fieldNames = new java.util.HashSet<>();
    private int tempCounter;
    private int callCounter;

    private List<FunctionSummary.AssignFact> assignments;
    private List<FunctionSummary.CallFact> calls;
    private List<FunctionSummary.ReturnFact> returns;
    private List<FunctionSummary.SourceFact> sources;
    private List<FunctionSummary.SinkFact> sinks;
    private List<FunctionSummary.AliasFact> aliases;
    private ClassModel model;

    /** Summarizes every method of one compilation unit; order is deterministic. */
    public List<FunctionSummary> summarizeUnit(JavaAst.CompilationUnit unit, AnalysisRules rules,
                                               ClassModel model) {
        this.model = model;
        List<FunctionSummary> out = new ArrayList<>();
        for (JavaAst.TypeDecl type : unit.types()) {
            summarizeType(unit, type, out);
        }
        return List.copyOf(out);
    }

    /** Overload used when no class model is available yet (testing/standalone use). */
    public List<FunctionSummary> summarizeUnit(JavaAst.CompilationUnit unit, AnalysisRules rules) {
        java.util.List<TypeMeta> metas = new ArrayList<>();
        java.util.Map<String, List<String>> importsByType = new java.util.TreeMap<>();
        java.util.Map<String, List<ClassModel.MethodSig>> methodsByType = new java.util.TreeMap<>();
        for (JavaAst.TypeDecl type : unit.types()) {
            collectMeta(type, unit.packageName(), unit.imports(), metas, importsByType, methodsByType);
        }
        return summarizeUnit(unit, rules,
                ClassModel.build(metas, importsByType, methodsByType));
    }

    private void collectMeta(JavaAst.TypeDecl type, String packageName, List<String> unitImports,
                             java.util.List<TypeMeta> metas,
                             java.util.Map<String, List<String>> importsByType,
                             java.util.Map<String, List<ClassModel.MethodSig>> methodsByType) {
        List<String> supers = new ArrayList<>(type.extendsNames());
        supers.addAll(type.implementsNames());
        java.util.Map<String, String> fields = new java.util.TreeMap<>();
        List<ClassModel.MethodSig> sigs = new ArrayList<>();
        for (JavaAst.Member member : type.members()) {
            if (member instanceof JavaAst.FieldDecl field) {
                for (JavaAst.VariableDeclarator d : field.declarators()) {
                    fields.put(d.name(), field.type());
                }
            } else if (member instanceof JavaAst.MethodDecl method) {
                sigs.add(new ClassModel.MethodSig(
                        method.isConstructor() ? INIT : method.name(),
                        method.params().size(), method.isStatic(), method.isConstructor()));
            } else if (member instanceof JavaAst.NestedTypeMember nested) {
                collectMeta(nested.type(), type.qualifiedName(), unitImports,
                        metas, importsByType, methodsByType);
            }
        }
        metas.add(new TypeMeta(type.qualifiedName(), packageName, type.name(),
                List.copyOf(supers), Map.copyOf(fields), type.isInterface()));
        importsByType.put(type.qualifiedName(), List.copyOf(unitImports));
        methodsByType.put(type.qualifiedName(), List.copyOf(sigs));
    }

    private void summarizeType(JavaAst.CompilationUnit unit, JavaAst.TypeDecl type,
                               List<FunctionSummary> out) {
        List<JavaAst.Stmt> instanceInits = new ArrayList<>();
        List<JavaAst.Stmt> staticInits = new ArrayList<>();
        List<JavaAst.MethodDecl> explicitCtors = new ArrayList<>();
        boolean interfaceOrAbstract = type.isInterface();

        for (JavaAst.Member member : orderedMembers(type)) {
            if (member instanceof JavaAst.MethodDecl method) {
                if (method.isConstructor()) {
                    explicitCtors.add(method);
                } else {
                    out.add(summarizeMethod(unit, type, method));
                }
            } else if (member instanceof JavaAst.FieldDecl field) {
                List<JavaAst.Stmt> inits = fieldInitializers(field);
                if (field.isStatic()) {
                    staticInits.addAll(inits);
                } else {
                    instanceInits.addAll(inits);
                }
            } else if (member instanceof JavaAst.InitBlock block) {
                if (block.isStatic()) {
                    staticInits.addAll(block.body());
                } else {
                    instanceInits.addAll(block.body());
                }
            } else if (member instanceof JavaAst.NestedTypeMember nested) {
                summarizeType(unit, nested.type(), out);
            }
        }

        List<JavaAst.Stmt> ctorPrefix = List.copyOf(instanceInits);
        if (explicitCtors.isEmpty() && !interfaceOrAbstract) {
            JavaAst.MethodDecl synthetic = new JavaAst.MethodDecl(INIT, ownerQType(type),
                    List.of(), ctorPrefix, List.of(), false, true, type.qualifiedName(),
                    unit.file(), type.line());
            out.add(summarizeMethod(unit, type, synthetic));
        } else {
            for (JavaAst.MethodDecl ctor : explicitCtors) {
                List<JavaAst.Stmt> body = new ArrayList<>(ctorPrefix);
                body.addAll(ctor.body());
                out.add(summarizeMethod(unit, type,
                        new JavaAst.MethodDecl(ctor.name(), ctor.returnType(), ctor.params(),
                                List.copyOf(body), ctor.modifiers(), ctor.isStatic(), true,
                                ctor.ownerQualifiedName(), ctor.file(), ctor.line())));
            }
        }
        if (!staticInits.isEmpty()) {
            JavaAst.MethodDecl clinit = new JavaAst.MethodDecl(CLINIT, "void",
                    List.of(), List.copyOf(staticInits), List.of("static"), true, false,
                    type.qualifiedName(), unit.file(), type.line());
            out.add(summarizeMethod(unit, type, clinit));
        }
    }

    private static String ownerQType(JavaAst.TypeDecl type) {
        return type.qualifiedName();
    }

    /** Members in source order; nested types included recursively elsewhere. */
    private static List<JavaAst.Member> orderedMembers(JavaAst.TypeDecl type) {
        return type.members();
    }

    private List<JavaAst.Stmt> fieldInitializers(JavaAst.FieldDecl field) {
        List<JavaAst.Stmt> stmts = new ArrayList<>();
        for (JavaAst.VariableDeclarator declarator : field.declarators()) {
            if (declarator.initializer() != null) {
                String name = field.isStatic()
                        ? STATIC_SCOPE + "." + declarator.name()
                        : THIS + "." + declarator.name();
                stmts.add(new JavaAst.ExpressionStmt(
                        new JavaAst.AssignExpr("=",
                                new JavaAst.IdentExpr(name, declarator.line()),
                                declarator.initializer(), declarator.line()),
                        declarator.line()));
            }
        }
        return stmts;
    }

    private FunctionSummary summarizeMethod(JavaAst.CompilationUnit unit,
                                            JavaAst.TypeDecl type,
                                            JavaAst.MethodDecl method) {
        this.fieldNames.clear();
        this.file = unit.file();
        this.imports = unit.imports();
        this.ownerQ = type.qualifiedName();
        this.ownerSimple = type.name();
        this.methodStatic = method.isStatic();
        this.constructor = method.isConstructor();
        this.params = new ArrayList<>();
        this.locals = new LinkedHashMap<>();
        this.tempCounter = 0;
        this.callCounter = 0;
        this.assignments = new ArrayList<>();
        this.calls = new ArrayList<>();
        this.returns = new ArrayList<>();
        this.sources = new ArrayList<>();
        this.sinks = new ArrayList<>();
        this.aliases = new ArrayList<>();

        List<String> paramNames = new ArrayList<>();
        if (!method.isStatic()) {
            paramNames.add(THIS);
        }
        for (JavaAst.Param p : method.params()) {
            paramNames.add(p.name());
            locals.put(p.name(), normalizeType(p.type()));
        }
        locals.put(THIS, type.qualifiedName());
        addFieldTypes(type);
        collectFieldNames(type);
        this.params = List.copyOf(paramNames);
        lowerStatements(method.body());

        String name = method.isConstructor() ? INIT : method.name();
        String functionName = ClassModel.methodId(type.qualifiedName(), name);
        return new FunctionSummary(functionName, file, this.params,
                List.copyOf(assignments), List.copyOf(calls), List.copyOf(returns),
                List.copyOf(sources), List.copyOf(sinks),
                type.qualifiedName(), method.isStatic(), method.isConstructor(),
                List.copyOf(imports), List.copyOf(aliases), Map.copyOf(locals), method.line());
    }

    /** Declared fields of the type are visible as local type hints for receivers. */
    private void addFieldTypes(JavaAst.TypeDecl type) {
        for (JavaAst.Member member : type.members()) {
            if (member instanceof JavaAst.FieldDecl field) {
                for (JavaAst.VariableDeclarator d : field.declarators()) {
                    locals.putIfAbsent(d.name(), normalizeType(field.type()));
                }
            }
        }
    }

    private void collectFieldNames(JavaAst.TypeDecl type) {
        for (JavaAst.Member member : type.members()) {
            if (member instanceof JavaAst.FieldDecl field) {
                for (JavaAst.VariableDeclarator d : field.declarators()) {
                    fieldNames.add(d.name());
                }
            }
        }
    }

    // ------------------------------------------------------------ statements

    private void lowerStatements(List<JavaAst.Stmt> stmts) {
        for (JavaAst.Stmt stmt : stmts) {
            lowerStatement(stmt);
        }
    }

    private void lowerStatement(JavaAst.Stmt stmt) {
        if (stmt instanceof JavaAst.LocalVarStmt decl) {
            for (JavaAst.VarDecl d : decl.declarators()) {
                locals.put(d.name(), normalizeType(d.type()));
                if (d.initializer() != null) {
                    lowerAssignment(new JavaAst.IdentExpr(d.name(), d.line()), d.initializer(), d.line());
                }
            }
        } else if (stmt instanceof JavaAst.ExpressionStmt e) {
            lowerExpressionForEffects(e.expr());
        } else if (stmt instanceof JavaAst.ReturnStmt r) {
            List<String> vars = new ArrayList<>();
            if (r.value() != null) {
                collectValueVars(r.value(), vars);
            }
            returns.add(new FunctionSummary.ReturnFact(List.copyOf(vars), r.line()));
        } else if (stmt instanceof JavaAst.ThrowStmt t) {
            lowerExpressionForEffects(t.value());
        } else if (stmt instanceof JavaAst.IfStmt i) {
            collectConditionEffects(i.cond());
            lowerStatements(i.thenBody());
            lowerStatements(i.elseBody());
        } else if (stmt instanceof JavaAst.WhileStmt w) {
            collectConditionEffects(w.cond());
            lowerStatements(w.body());
        } else if (stmt instanceof JavaAst.DoWhileStmt d) {
            lowerStatements(d.body());
            collectConditionEffects(d.cond());
        } else if (stmt instanceof JavaAst.ForStmt f) {
            lowerStatements(f.init());
            if (f.cond() != null) {
                collectConditionEffects(f.cond());
            }
            lowerStatements(f.body());
            for (JavaAst.Expr update : f.update()) {
                lowerExpressionForEffects(update);
            }
        } else if (stmt instanceof JavaAst.EnhancedForStmt ef) {
            locals.put(ef.varName(), normalizeType(ef.varType()));
            lowerExpressionForEffects(ef.iterable());
            lowerStatements(ef.body());
        } else if (stmt instanceof JavaAst.BlockStmt b) {
            lowerStatements(b.body());
        } else if (stmt instanceof JavaAst.TryStmt tr) {
            lowerStatements(tr.resources());
            lowerStatements(tr.body());
            for (JavaAst.CatchClause c : tr.catchClauses()) {
                locals.put(c.param(), normalizeType(c.paramType()));
                lowerStatements(c.body());
            }
            lowerStatements(tr.finallyBody());
        } else if (stmt instanceof JavaAst.SwitchStmt sw) {
            lowerExpressionForEffects(sw.selector());
            for (JavaAst.SwitchCase c : sw.cases()) {
                for (JavaAst.Expr label : c.labels()) {
                    lowerExpressionForEffects(label);
                }
                lowerStatements(c.body());
            }
        } else if (stmt instanceof JavaAst.LabeledStmt labeled) {
            lowerStatement(labeled.body());
        } else if (stmt instanceof JavaAst.SynchronizedStmt sync) {
            lowerExpressionForEffects(sync.monitor());
            lowerStatements(sync.body());
        } else if (stmt instanceof JavaAst.AssertStmt assertion) {
            collectConditionEffects(assertion.condition());
            if (assertion.detail() != null) {
                lowerExpressionForEffects(assertion.detail());
            }
        }
        // break/continue/empty carry no data flow
    }

    private void collectConditionEffects(JavaAst.Expr cond) {
        lowerExpressionForEffects(cond);
    }

    private static String normalizeType(String type) {
        if (type == null) {
            return "";
        }
        String t = type.replace("...", "[]").trim();
        int idx = t.indexOf('[');
        return idx < 0 ? t : t.substring(0, idx);
    }

    // ----------------------------------------------------------- expressions

    private String freshTemp() {
        return "$tmp" + (tempCounter++);
    }

    private void lowerAssignment(JavaAst.Expr target, JavaAst.Expr value, int line) {
        String dst = accessPath(target);
        boolean compound = value == null;
        List<String> srcs = new ArrayList<>();
        boolean isFieldWrite = dst.startsWith(THIS + ".") || dst.startsWith(STATIC_SCOPE + ".");
        if (value != null) {
            collectValueVars(value, srcs);
        }
        if (compound) {
            // compound assignment: dst op= expr  -> dst still depends on its old value
            srcs.add(0, dst);
        }
        if (!srcs.isEmpty()) {
            assignments.add(new FunctionSummary.AssignFact(dst, List.copyOf(srcs), line));
        }
        maybeAlias(dst, value, line);
    }

    private void lowerExpressionForEffects(JavaAst.Expr expr) {
        if (expr instanceof JavaAst.AssignExpr assign) {
            lowerAssignment(assign.target(), assign.value(), assign.line());
            return;
        }
        List<String> ignored = new ArrayList<>();
        collectValueVars(expr, ignored);
    }

    /** Reference-typed copy assignments share an object: record a bidirectional alias. */
    private void maybeAlias(String dst, JavaAst.Expr value, int line) {
        // A field WRITE (o.f = x) copies a value into a slot; it is not itself a
        // reference alias between two object roots.
        if (dst.indexOf('.') >= 0) {
            return;
        }
        if (value == null) {
            return;
        }
        String source = singleReferenceExpr(value);
        if (source != null && !source.equals(dst)) {
            aliases.add(new FunctionSummary.AliasFact(source, dst, line));
        }
    }

    /** If the expression denotes a single object reference (not a call/new), returns its path. */
    private String singleReferenceExpr(JavaAst.Expr expr) {
        if (expr instanceof JavaAst.IdentExpr id) {
            return isPrimitiveType(locals.get(id.name())) ? null : id.name();
        }
        if (expr instanceof JavaAst.ThisExpr) {
            return THIS;
        }
        if (expr instanceof JavaAst.FieldAccessExpr f) {
            return accessPath(f); // objects unless primitive; conservative inclusion
        }
        if (expr instanceof JavaAst.ParenExpr p) {
            return singleReferenceExpr(p.inner());
        }
        if (expr instanceof JavaAst.CastExpr c) {
            return singleReferenceExpr(c.operand());
        }
        return null;
    }

    private static boolean isPrimitiveType(String type) {
        return type != null && (type.equals("int") || type.equals("long") || type.equals("short")
                || type.equals("byte") || type.equals("char") || type.equals("boolean")
                || type.equals("float") || type.equals("double"));
    }

    /** Collects the access paths whose value taints this expression. */
    private void collectValueVars(JavaAst.Expr expr, List<String> out) {
        if (expr == null || expr instanceof JavaAst.LiteralExpr
                || expr instanceof JavaAst.LambdaExpr || expr instanceof JavaAst.MethodRefExpr) {
            return;
        }
        if (expr instanceof JavaAst.IdentExpr id) {
            addDistinct(resolveIdent(id.name(), id.line()), out);
        } else if (expr instanceof JavaAst.ThisExpr || expr instanceof JavaAst.SuperExpr) {
            addDistinct(THIS, out);
        } else if (expr instanceof JavaAst.ParenExpr p) {
            collectValueVars(p.inner(), out);
        } else if (expr instanceof JavaAst.UnaryExpr u && u.operand() != null) {
            collectValueVars(u.operand(), out);
        } else if (expr instanceof JavaAst.CastExpr c) {
            collectValueVars(c.operand(), out);
        } else if (expr instanceof JavaAst.BinaryExpr b) {
            collectValueVars(b.left(), out);
            collectValueVars(b.right(), out);
        } else if (expr instanceof JavaAst.ConditionalExpr c) {
            collectValueVars(c.condition(), out);
            collectValueVars(c.thenValue(), out);
            collectValueVars(c.elseValue(), out);
        } else if (expr instanceof JavaAst.InstanceOfExpr io) {
            collectValueVars(io.value(), out);
        } else if (expr instanceof JavaAst.ArrayAccessExpr a) {
            collectValueVars(a.array(), out);
            collectValueVars(a.index(), out);
        } else if (expr instanceof JavaAst.ArrayInitExpr arr) {
            for (JavaAst.Expr element : arr.elements()) {
                collectValueVars(element, out);
            }
        } else if (expr instanceof JavaAst.NewArrayExpr na) {
            for (JavaAst.Expr dim : na.dimensions()) {
                collectValueVars(dim, out);
            }
            for (JavaAst.Expr element : na.initializer()) {
                collectValueVars(element, out);
            }
        } else if (expr instanceof JavaAst.FieldAccessExpr f) {
            addDistinct(accessPath(f), out);
        } else if (expr instanceof JavaAst.AssignExpr a) {
            lowerAssignment(a.target(), a.value(), a.line());
            addDistinct(accessPath(a.target()), out);
        } else if (expr instanceof JavaAst.CallExpr call) {
            addDistinct(lowerCall(call, null), out);
        } else if (expr instanceof JavaAst.NewExpr neu) {
            addDistinct(lowerNew(neu), out);
        }
    }

    private static void addDistinct(String path, List<String> out) {
        if (path != null && !out.contains(path)) {
            out.add(path);
        }
    }

    // ------------------------------------------------------ access paths

    private String resolveIdent(String name, int line) {
        if ("this".equals(name)) {
            return THIS;
        }
        if ("super".equals(name)) {
            return THIS;
        }
        // A bare name shadows in order: locals/params, then this class's fields,
        // then unresolved names. Field reads normalize to $this.name so they
        // share a node with explicit this.name accesses.
        if (locals.containsKey(name)) {
            return name;
        }
        if (fieldNames.contains(name)) {
            return THIS + "." + name;
        }
        return name;
    }

    /** Access path of an lvalue/rvalue expression used as a field selection. */
    private String accessPath(JavaAst.Expr expr) {
        if (expr instanceof JavaAst.IdentExpr id) {
            return id.name();
        }
        if (expr instanceof JavaAst.ThisExpr) {
            return THIS;
        }
        if (expr instanceof JavaAst.SuperExpr) {
            return THIS;
        }
        if (expr instanceof JavaAst.ParenExpr p) {
            return accessPath(p.inner());
        }
        if (expr instanceof JavaAst.ArrayAccessExpr a) {
            return accessPath(a.array()); // array elements collapse to the array object
        }
        if (expr instanceof JavaAst.FieldAccessExpr f) {
            return fieldAccessPath(f);
        }
        return "$expr";
    }

    private String fieldAccessPath(JavaAst.FieldAccessExpr f) {
        // Static field: Type.f  (Type is resolvable, target is a type-name chain)
        String staticOwner = typeNameOf(f.target());
        if (staticOwner != null) {
            String resolved = model.resolveType(ownerQ, staticOwner);
            if (resolved != null) {
                return STATIC_SCOPE + "." + resolved + "." + f.name();
            }
            // possibly external static field; keep canonical shape $static.Type.name
            return STATIC_SCOPE + "." + staticOwner + "." + f.name();
        }
        String receiver = accessPath(f.target());
        return receiver + "." + f.name();
    }

    /**
     * Returns the fully/simple dotted type name if the expression consists solely
     * of identifiers (a type-name chain), otherwise null.
     */
    private String typeNameOf(JavaAst.Expr expr) {
        if (expr instanceof JavaAst.IdentExpr id) {
            // bare ident: could be a local/field too; a type only if not a known local
            if (locals.containsKey(id.name())) {
                return null;
            }
            if (THIS.equals(id.name())) {
                return null;
            }
            // Heuristic: capitalized or resolvable via imports -> treat as a type.
            return looksLikeTypeName(id.name()) ? id.name() : null;
        }
        if (expr instanceof JavaAst.FieldAccessExpr f) {
            String head = typeNameOf(f.target());
            return head == null ? null : head + "." + f.name();
        }
        return null;
    }

    private boolean looksLikeTypeName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (Character.isUpperCase(name.charAt(0))) {
            return true;
        }
        return model.resolveType(ownerQ, name) != null;
    }

    // ------------------------------------------------------------- calls

    private String lowerCall(JavaAst.CallExpr call, String dst) {
        String resultVar = dst == null ? freshTemp() : dst;
        List<String> argVars = new ArrayList<>();
        for (JavaAst.Expr arg : call.args()) {
            collectValueVars(arg, argVars);
        }
        String name = call.name();
        String receiverVar = null;
        String qualifierType = null;

        if (call.target() == null) {
            // unqualified call: static-import / same-class / other-class resolution
            // decided later by the engine using the context class and arity.
            receiverVar = methodStatic ? null : THIS;
        } else if (call.target() instanceof JavaAst.ThisExpr || call.target() instanceof JavaAst.SuperExpr) {
            receiverVar = THIS;
        } else {
            String typeName = typeNameOf(call.target());
            if (typeName != null) {
                qualifierType = typeName;
            } else {
                receiverVar = accessPath(call.target());
            }
        }
        String callSiteId = file + ":" + call.line() + ":" + (callCounter++);
        calls.add(new FunctionSummary.CallFact(callSiteId, name, List.copyOf(argVars), resultVar,
                call.line(), receiverVar, qualifierType, null, call.args().size()));
        return resultVar;
    }

    private String lowerNew(JavaAst.NewExpr neu) {
        List<String> argVars = new ArrayList<>();
        for (JavaAst.Expr arg : neu.args()) {
            collectValueVars(arg, argVars);
        }
        String dst = freshTemp();
        String callSiteId = file + ":" + neu.line() + ":" + (callCounter++);
        calls.add(new FunctionSummary.CallFact(callSiteId, INIT, List.copyOf(argVars), dst,
                neu.line(), null, neu.typeName(), neu.typeName(), neu.args().size()));
        return dst;
    }
}
