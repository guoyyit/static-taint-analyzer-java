package com.github.guoyyit.statictaintanalyzerjava.lang;

import com.github.guoyyit.statictaintanalyzerjava.analysis.FunctionSummary;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.ArrayAccessExpr;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.InstanceOfExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.MethodReferenceExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SuperExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.AssertStmt;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.DoStmt;
import com.github.javaparser.ast.stmt.ExplicitConstructorInvocationStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.LabeledStmt;
import com.github.javaparser.ast.stmt.LocalClassDeclarationStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchEntry;
import com.github.javaparser.ast.stmt.SwitchStmt;
import com.github.javaparser.ast.stmt.SynchronizedStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.github.javaparser.ast.stmt.YieldStmt;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Lowers one Java member (method, constructor, field initializer, class
 * initializer) into {@link FunctionSummary} flow facts. Package-visible and
 * created only by {@link JavaFrontend}.
 *
 * <p>The lowering is order-insensitive with respect to taint (all branches are
 * merged), bounded, and over-approximate: an unresolved field access is also
 * treated as a local read and vice-versa, so taint is never silently dropped.
 */
final class MemberLowerer {

    enum Kind { METHOD, CONSTRUCTOR, FIELD, STATIC }

    private static final String THIS = "$this";

    private final String file;
    private final String ownerFqn;
    private final String memberName;
    private final String packageName;
    private final List<String> imports;
    private final List<String> supers;
    private final boolean isStatic;
    private final Kind kind;

    private final List<String> params = new ArrayList<>();
    private final List<String> paramTypes = new ArrayList<>();
    private final List<FunctionSummary.AssignFact> assignments = new ArrayList<>();
    private final List<FunctionSummary.CallFact> calls = new ArrayList<>();
    private final List<FunctionSummary.ReturnFact> returns = new ArrayList<>();
    private final List<FunctionSummary.FieldWriteFact> fieldWrites = new ArrayList<>();
    private final List<FunctionSummary.FieldReadFact> fieldReads = new ArrayList<>();
    private final Set<String> locals = new LinkedHashSet<>();
    private int tempCounter;
    private int callCounter;

    MemberLowerer(String file, String ownerFqn, String memberName, String packageName,
                  List<String> imports, List<String> supers, boolean isStatic, Kind kind) {
        this.file = file;
        this.ownerFqn = ownerFqn;
        this.memberName = memberName;
        this.packageName = packageName;
        this.imports = imports;
        this.supers = supers;
        this.isStatic = isStatic;
        this.kind = kind;
    }

    void addThisParam() {
        params.add(THIS);
        paramTypes.add(ownerFqn);
    }

    void addParam(String name, String type) {
        params.add(name);
        paramTypes.add(type == null ? "" : type);
        locals.add(name);
    }

    void lowerParams(MethodDeclaration m) {
        for (var p : m.getParameters()) {
            addParam(p.getNameAsString(), JavaFrontend.cleanType(p.getType()));
        }
    }

    void lowerParams(com.github.javaparser.ast.body.CallableDeclaration<?> callable) {
        for (var p : callable.getParameters()) {
            addParam(p.getNameAsString(), JavaFrontend.cleanType(p.getType()));
        }
    }

    void lowerBlock(BlockStmt block) {
        for (Statement stmt : block.getStatements()) {
            lowerStmt(stmt);
        }
    }

    FunctionSummary build(int line) {
        String key = memberKey();
        boolean instance = !isStatic && (kind == Kind.METHOD || kind == Kind.CONSTRUCTOR);
        return new FunctionSummary(key, file, List.copyOf(params),
                List.copyOf(assignments), List.copyOf(calls), List.copyOf(returns),
                List.of(), List.of(),
                ownerFqn, memberName, packageName,
                List.copyOf(paramTypes), imports, List.copyOf(supers), instance,
                List.copyOf(fieldWrites), List.copyOf(fieldReads));
    }

    private String memberKey() {
        if (kind == Kind.METHOD) {
            return ownerFqn + "#" + memberName + "(" + String.join(",", paramTypes) + ")";
        }
        if (kind == Kind.CONSTRUCTOR) {
            // $this occupies the first param slot
            List<String> declaredTypes = paramTypes.size() <= 1 ? List.of()
                    : paramTypes.subList(1, paramTypes.size());
            return ownerFqn + "#<init>(" + String.join(",", declaredTypes) + ")";
        }
        return ownerFqn + "#" + memberName;
    }

    // ------------------------------------------------------------- statements

    void lowerStmt(Statement stmt) {
        if (stmt instanceof BlockStmt b) {
            lowerBlock(b);
        } else if (stmt instanceof ExpressionStmt e) {
            lowerExpr(e.getExpression());
        } else if (stmt instanceof ReturnStmt r) {
            if (r.getExpression().isPresent()) {
                addReturn(lowerExpr(r.getExpression().get()), JavaFrontend.lineOf(r));
            }
        } else if (stmt instanceof IfStmt i) {
            lowerExpr(i.getCondition());
            lowerStmt(i.getThenStmt());
            i.getElseStmt().ifPresent(this::lowerStmt);
        } else if (stmt instanceof WhileStmt w) {
            lowerExpr(w.getCondition());
            lowerStmt(w.getBody());
        } else if (stmt instanceof DoStmt d) {
            lowerStmt(d.getBody());
            lowerExpr(d.getCondition());
        } else if (stmt instanceof ForStmt f) {
            f.getInitialization().forEach(this::lowerExpr);
            f.getCompare().ifPresent(this::lowerExpr);
            f.getUpdate().forEach(this::lowerExpr);
            lowerStmt(f.getBody());
        } else if (stmt instanceof ForEachStmt f) {
            lowerExpr(f.getIterable());
            lowerExpr(f.getVariable());
            List<String> varNames = varNames(f.getVariable());
            locals.addAll(varNames);
            for (String name : varNames) {
                assignments.add(new FunctionSummary.AssignFact(name,
                        lowerExpr(f.getIterable()), JavaFrontend.lineOf(f)));
            }
            lowerStmt(f.getBody());
        } else if (stmt instanceof SwitchStmt s) {
            lowerExpr(s.getSelector());
            for (SwitchEntry entry : s.getEntries()) {
                entry.getLabels().forEach(this::lowerExpr);
                if (entry.getGuard().isPresent()) {
                    lowerExpr(entry.getGuard().get());
                }
                entry.getStatements().forEach(this::lowerStmt);
            }
        } else if (stmt instanceof TryStmt t) {
            t.getResources().forEach(this::lowerExpr);
            lowerBlock(t.getTryBlock());
            for (CatchClause clause : t.getCatchClauses()) {
                locals.add(clause.getParameter().getNameAsString());
                clause.getBody().getStatements().forEach(this::lowerStmt);
            }
            t.getFinallyBlock().ifPresent(this::lowerBlock);
        } else if (stmt instanceof ThrowStmt t) {
            lowerExpr(t.getExpression());
        } else if (stmt instanceof AssertStmt a) {
            lowerExpr(a.getCheck());
            a.getMessage().ifPresent(this::lowerExpr);
        } else if (stmt instanceof SynchronizedStmt s) {
            lowerExpr(s.getExpression());
            lowerBlock(s.getBody());
        } else if (stmt instanceof ExplicitConstructorInvocationStmt c) {
            lowerExplicitCtor(c);
        } else if (stmt instanceof YieldStmt y) {
            lowerExpr(y.getExpression());
        } else if (stmt instanceof LabeledStmt l) {
            lowerStmt(l.getStatement());
        } else if (stmt instanceof LocalClassDeclarationStmt l) {
            // Members of local classes are collected top-down by the frontend;
            // nothing to lower in the enclosing flow.
        }
        // Empty, break, continue and unknown statements carry no data flow.
    }

    private void lowerExplicitCtor(ExplicitConstructorInvocationStmt c) {
        List<String> args = new ArrayList<>();
        for (Expression arg : c.getArguments()) {
            args.addAll(lowerExpr(arg));
        }
        int line = JavaFrontend.lineOf(c);
        List<String> owners = new ArrayList<>();
        if (c.isThis()) {
            owners.add(ownerFqn);
            owners.add("$this*");
        } else {
            owners.addAll(supers);
        }
        if (!c.isThis() && c.getExpression().isPresent()) {
            // super call via an enclosing instance: no resolvable static owner
            lowerExpr(c.getExpression().get());
        }
        String calleeText = c.isThis() ? "<init>" : "<init>";
        emitCall("<init>", args, null, owners, false, true, List.of(), line);
    }

    void addReturn(List<String> srcs, int line) {
        returns.add(new FunctionSummary.ReturnFact(List.copyOf(srcs), line));
    }

    // ------------------------------------------------------------ expressions

    /** Lowers an expression, returning the local temp/var names carrying its value. */
    List<String> lowerExpr(Expression expr) {
        if (expr == null) {
            return List.of();
        }
        if (expr instanceof NameExpr n) {
            return lowerName(n.getNameAsString(), n);
        }
        if (expr instanceof LiteralExpr) {
            return List.of();
        }
        if (expr instanceof ThisExpr) {
            return List.of(THIS);
        }
        if (expr instanceof SuperExpr) {
            return List.of(THIS);
        }
        if (expr instanceof com.github.javaparser.ast.expr.EnclosedExpr e) {
            return lowerExpr(e.getInner());
        }
        if (expr instanceof UnaryExpr u) {
            return lowerExpr(u.getExpression());
        }
        if (expr instanceof CastExpr c) {
            return lowerExpr(c.getExpression());
        }
        if (expr instanceof BinaryExpr b) {
            List<String> vars = new ArrayList<>(lowerExpr(b.getLeft()));
            vars.addAll(lowerExpr(b.getRight()));
            return vars;
        }
        if (expr instanceof ConditionalExpr c) {
            lowerExpr(c.getCondition());
            List<String> vars = new ArrayList<>(lowerExpr(c.getThenExpr()));
            vars.addAll(lowerExpr(c.getElseExpr()));
            return vars;
        }
        if (expr instanceof InstanceOfExpr i) {
            return lowerExpr(i.getExpression());
        }
        if (expr instanceof ArrayAccessExpr a) {
            lowerExpr(a.getIndex());
            return lowerExpr(a.getName());
        }
        if (expr instanceof ArrayCreationExpr a) {
            if (a.getInitializer().isPresent()) {
                return lowerExpr(a.getInitializer().get());
            }
            a.getLevels().forEach(level -> level.getDimension().ifPresent(this::lowerExpr));
            return List.of();
        }
        if (expr instanceof ArrayInitializerExpr a) {
            List<String> vars = new ArrayList<>();
            for (Expression value : a.getValues()) {
                vars.addAll(lowerExpr(value));
            }
            return vars;
        }
        if (expr instanceof AssignExpr a) {
            return lowerAssign(a);
        }
        if (expr instanceof VariableDeclarationExpr v) {
            return lowerVarDecl(v);
        }
        if (expr instanceof MethodCallExpr m) {
            return lowerMethodCall(m, null);
        }
        if (expr instanceof ObjectCreationExpr o) {
            return lowerObjectCreation(o);
        }
        if (expr instanceof FieldAccessExpr f) {
            return lowerFieldAccessValue(f);
        }
        if (expr instanceof LambdaExpr l) {
            for (var p : l.getParameters()) {
                locals.add(p.getNameAsString());
            }
            if (l.getExpressionBody().isPresent()) {
                return lowerExpr(l.getExpressionBody().get());
            }
            lowerStmt(l.getBody());
            return List.of();
        }
        if (expr instanceof MethodReferenceExpr) {
            return List.of();
        }
        if (expr instanceof com.github.javaparser.ast.expr.SwitchExpr s) {
            lowerExpr(s.getSelector());
            List<String> vars = new ArrayList<>();
            for (SwitchEntry entry : s.getEntries()) {
                entry.getLabels().forEach(this::lowerExpr);
                for (Statement st : entry.getStatements()) {
                    if (st instanceof YieldStmt y && y.getExpression() != null) {
                        vars.addAll(lowerExpr(y.getExpression()));
                    } else {
                        lowerStmt(st);
                    }
                }
            }
            return vars;
        }
        // Annotation and other value-free expressions: conservative empty.
        return List.of();
    }

    private List<String> lowerName(String name, Node node) {
        if (locals.contains(name) || THIS.equals(name)) {
            return List.of(name);
        }
        // Unqualified name could be a field (this/super/static) or an unresolved
        // local: over-approximate by emitting a field read temp while also
        // keeping the bare name, so neither carrier is dropped.
        List<String> owners = new ArrayList<>();
        owners.add(ownerFqn);
        owners.add("$this*");
        for (String sup : supers) {
            owners.add(sup);
        }
        addStaticOwnerHints(name, owners);
        String temp = fieldRead(name, owners, JavaFrontend.lineOf(node));
        List<String> vars = new ArrayList<>();
        vars.add(name);
        vars.add(temp);
        return vars;
    }

    private List<String> lowerAssign(AssignExpr a) {
        List<String> srcs = new ArrayList<>(lowerExpr(a.getValue()));
        int line = JavaFrontend.lineOf(a);
        Expression target = a.getTarget();
        if (target instanceof NameExpr n) {
            if (locals.contains(n.getNameAsString())) {
                assignments.add(new FunctionSummary.AssignFact(n.getNameAsString(), srcs, line));
            } else {
                // Could be a field access without explicit this.
                List<String> owners = new ArrayList<>();
                owners.add(ownerFqn);
                owners.add("$this*");
                addStaticOwnerHints(n.getNameAsString(), owners);
                fieldWrite(n.getNameAsString(), owners, srcs, line);
            }
        } else if (target instanceof FieldAccessExpr f) {
            lowerFieldAccessWrite(f, srcs, line);
        } else if (target instanceof ArrayAccessExpr arr) {
            lowerExpr(arr.getIndex());
            List<String> carriers = carrierOf(arr.getName());
            // Alias containers: array element write makes the array carrier tainted
            for (String carrier : carriers) {
                if (locals.contains(carrier)) {
                    assignments.add(new FunctionSummary.AssignFact(carrier, srcs, line));
                }
            }
        }
        if (a.getOperator() != AssignExpr.Operator.ASSIGN) {
            // compound assignment (+=, ...): target also contributes its old value
            srcs = new ArrayList<>(srcs);
            srcs.addAll(carrierOf(target));
        }
        return srcs;
    }

    private List<String> lowerVarDecl(VariableDeclarationExpr v) {
        List<String> all = new ArrayList<>();
        for (var declarator : v.getVariables()) {
            String name = declarator.getNameAsString();
            locals.add(name);
            String declaredType = v.getCommonType().isUnknownType()
                    ? null : JavaFrontend.cleanType(v.getCommonType());
            if (declaredType != null && !declaredType.isBlank() && !"var".equals(declaredType)) {
                localTypes.put(name, declaredType);
            }
            declarator.getInitializer().ifPresent(init -> {
                List<String> srcs = lowerExpr(init);
                if (init instanceof ObjectCreationExpr oce
                        && (declaredType == null || "var".equals(declaredType))) {
                    localTypes.put(name, JavaFrontend.cleanType(oce.getType()));
                }
                if (!srcs.isEmpty()) {
                    assignments.add(new FunctionSummary.AssignFact(name, List.copyOf(srcs),
                            JavaFrontend.lineOf(declarator)));
                }
            });
            all.add(name);
        }
        return all;
    }

    private List<String> lowerMethodCall(MethodCallExpr m, String forcedDst) {
        List<String> args = new ArrayList<>();
        for (Expression arg : m.getArguments()) {
            args.addAll(lowerExpr(arg));
        }
        int line = JavaFrontend.lineOf(m);
        List<String> owners = new ArrayList<>();
        List<String> receiverVars = new ArrayList<>();
        boolean looksStatic = false;
        if (m.getScope().isPresent()) {
            Expression scope = m.getScope().get();
            if (scope instanceof NameExpr n) {
                List<String> tokens = nameTokens(n.getNameAsString());
                // A capitalized simple name that is not a local is treated as a type.
                if (!locals.contains(n.getNameAsString()) && isTypeName(tokens)) {
                    owners.addAll(tokens);
                    looksStatic = true;
                } else {
                    receiverVars.addAll(lowerName(n.getNameAsString(), n));
                    owners.addAll(typeHintsForVar(n.getNameAsString(), tokens));
                }
            } else if (scope instanceof FieldAccessExpr f) {
                List<String> tokens = fieldAccessTokens(f);
                if (isTypeName(tokens)) {
                    owners.addAll(tokens);
                    looksStatic = true;
                } else {
                    receiverVars.addAll(lowerFieldAccessValue(f));
                    owners.addAll(tokens);
                }
            } else if (scope instanceof MethodCallExpr inner) {
                // Nested call as receiver: the inner result's inferred type is our owner.
                List<String> innerVars = lowerMethodCall(inner, null);
                receiverVars.addAll(innerVars);
                for (String v : innerVars) {
                    String t = localTypes.get(v);
                    if (t != null) {
                        owners.addAll(nameTokens(t));
                    }
                }
            } else {
                receiverVars.addAll(lowerExpr(scope));
            }
        } else {
            owners.add(ownerFqn);
            owners.add("$this*");
            for (String sup : supers) {
                owners.add(sup);
            }
            addStaticImportHints(m.getNameAsString(), owners);
        }
        String dst = forcedDst;
        String temp = null;
        if (dst == null) {
            temp = freshTemp();
            dst = temp;
        }
        List<String> resultHints = inferResultTypeHints(m, owners, looksStatic);
        emitCall(m.getNameAsString(), args, dst, owners, looksStatic, false, receiverVars,
                resultHints, line);
        return temp == null ? List.of() : List.of(temp);
    }

    /**
     * Intra-procedural guess of a call result's type. An instance method result
     * is assumed assignable to the receiver type (covers fluent {@code return this}
     * chains). Static method return types cannot be known without resolution, so
     * the global graph conservatively propagates argument taint in that case.
     */
    private List<String> inferResultTypeHints(MethodCallExpr m, List<String> owners, boolean looksStatic) {
        if (looksStatic) {
            return List.of();
        }
        List<String> hints = new ArrayList<>();
        for (String token : owners) {
            if (token != null && looksLikeTypeToken(token)) {
                hints.add(token);
            }
        }
        return dedup(hints);
    }

    private static boolean looksLikeTypeToken(String token) {
        if (token == null || token.isEmpty() || "$this*".equals(token)) {
            return false;
        }
        String head = token.contains(".") ? token.substring(0, token.indexOf('.')) : token;
        return Character.isUpperCase(head.charAt(0));
    }

    private List<String> lowerObjectCreation(ObjectCreationExpr o) {
        List<String> args = new ArrayList<>();
        for (Expression arg : o.getArguments()) {
            args.addAll(lowerExpr(arg));
        }
        int line = JavaFrontend.lineOf(o);
        List<String> owners = new ArrayList<>(nameTokens(JavaFrontend.cleanType(o.getType())));
        o.getScope().ifPresent(s -> lowerExpr(s));
        String temp = freshTemp();
        // The constructed object aliases every field its constructor writes.
        emitCall("<init>", args, temp, owners, false, true, List.of(),
                List.of(JavaFrontend.cleanType(o.getType())), line);
        return List.of(temp);
    }

    private List<String> lowerFieldAccessValue(FieldAccessExpr f) {
        int line = JavaFrontend.lineOf(f);
        List<String> tokens = fieldAccessTokens(f);
        String field = f.getNameAsString();
        if (f.getScope() instanceof NameExpr n && !locals.contains(n.getNameAsString())
                && isTypeName(tokens)) {
            // static field access: owner is the type prefix
            return List.of(fieldRead(field, tokens, line));
        }
        List<String> owners = new ArrayList<>(tokens);
        if (f.getScope() instanceof ThisExpr || f.getScope() instanceof SuperExpr) {
            owners.add(ownerFqn);
            owners.add("$this*");
            owners.add("this");
        }
        List<String> receivers = lowerExpr(f.getScope());
        if (receivers.contains(THIS)) {
            owners.add(ownerFqn);
            owners.add("$this*");
        }
        for (String sup : supers) {
            owners.add(sup);
        }
        if (f.getScope() instanceof SuperExpr) {
            owners.add("super");
        }
        String temp = fieldRead(field, owners, line);
        List<String> vars = new ArrayList<>();
        vars.add(temp);
        vars.addAll(receivers);
        return vars;
    }

    private void lowerFieldAccessWrite(FieldAccessExpr f, List<String> srcs, int line) {
        List<String> tokens = fieldAccessTokens(f);
        String field = f.getNameAsString();
        List<String> owners = new ArrayList<>(tokens);
        List<String> receivers = List.of();
        if (!(f.getScope() instanceof NameExpr n && !locals.contains(n.getNameAsString())
                && isTypeName(tokens))) {
            receivers = lowerExpr(f.getScope());
            if (receivers.contains(THIS) || f.getScope() instanceof ThisExpr
                    || f.getScope() instanceof SuperExpr) {
                owners.add(ownerFqn);
                owners.add("$this*");
            }
            for (String sup : supers) {
                owners.add(sup);
            }
        }
        fieldWrite(field, owners, srcs, line);
        // object alias: writing a field taints the carrier object too
        for (String receiver : receivers) {
            if (!THIS.equals(receiver)) {
                assignments.add(new FunctionSummary.AssignFact(receiver, srcs, line));
            }
        }
    }

    // --------------------------------------------------------------- helpers

    private final java.util.Map<String, String> localTypes = new java.util.LinkedHashMap<>();

    private String freshTemp() {
        return "$t" + (tempCounter++);
    }

    String fieldRead(String field, List<String> owners, int line) {
        String temp = freshTemp();
        fieldReads.add(new FunctionSummary.FieldReadFact(temp, field, dedup(owners), line));
        return temp;
    }

    void fieldWrite(String field, List<String> owners, List<String> srcs, int line) {
        fieldWrites.add(new FunctionSummary.FieldWriteFact(field, dedup(owners), List.copyOf(srcs), line));
    }

    private void emitCall(String callee, List<String> args, String dst, List<String> owners,
                          boolean looksStatic, boolean isConstructor, List<String> receiverVars, int line) {
        emitCall(callee, args, dst, owners, looksStatic, isConstructor, receiverVars, List.of(), line);
    }

    private void emitCall(String callee, List<String> args, String dst, List<String> owners,
                          boolean looksStatic, boolean isConstructor, List<String> receiverVars,
                          List<String> resultTypeHints, int line) {
        String callSiteId = file + ":" + line + ":" + (callCounter++);
        FunctionSummary.JavaCall javaCall = new FunctionSummary.JavaCall(
                dedup(owners), looksStatic, isConstructor, dedup(receiverVars), dedup(resultTypeHints));
        calls.add(new FunctionSummary.CallFact(callSiteId, callee, List.copyOf(args), dst, line, javaCall));
        if (dst != null && dst.startsWith("$t") && !resultTypeHints.isEmpty()) {
            localTypes.put(dst, resultTypeHints.get(0));
        }
    }

    private static List<String> dedup(List<String> values) {
        return new ArrayList<>(new LinkedHashSet<>(values));
    }

    private List<String> varNames(VariableDeclarationExpr v) {
        List<String> names = new ArrayList<>();
        for (var d : v.getVariables()) {
            names.add(d.getNameAsString());
        }
        return names;
    }

    private List<String> carrierOf(Expression expr) {
        if (expr == null) {
            return List.of();
        }
        if (expr instanceof NameExpr n) {
            return List.of(n.getNameAsString());
        }
        if (expr instanceof ThisExpr || expr instanceof SuperExpr) {
            return List.of(THIS);
        }
        return lowerExpr(expr);
    }

    private List<String> typeHintsForVar(String var, List<String> rawTokens) {
        List<String> hints = new ArrayList<>(rawTokens);
        if (THIS.equals(var)) {
            hints.add(ownerFqn);
            hints.add("$this*");
            return dedup(hints);
        }
        String type = localTypes.get(var);
        if (type != null) {
            hints.addAll(nameTokens(type));
        }
        return hints;
    }

    private List<String> fieldAccessTokens(FieldAccessExpr f) {
        String scopeText = f.getScope().toString().replaceAll("\\s+", "");
        List<String> tokens = new ArrayList<>(nameTokens(scopeText));
        if (f.getScope() instanceof NameExpr n) {
            String type = localTypes.get(n.getNameAsString());
            if (type != null) {
                tokens.addAll(nameTokens(type));
            }
        }
        return tokens;
    }

    /** All suffixes of a dotted name: {@code a.b.C -> [a.b.C, b.C, C]}. */
    static List<String> nameTokens(String dotted) {
        if (dotted == null || dotted.isBlank()) {
            return List.of();
        }
        String[] parts = dotted.split("\\.");
        List<String> tokens = new ArrayList<>();
        for (int i = 0; i < parts.length; i++) {
            tokens.add(String.join(".", java.util.Arrays.copyOfRange(parts, i, parts.length)));
        }
        return tokens;
    }

    private static boolean isTypeName(List<String> tokens) {
        for (String token : tokens) {
            String head = token.contains(".") ? token.substring(0, token.indexOf('.')) : token;
            if (!head.isEmpty() && Character.isUpperCase(head.charAt(0))) {
                return true;
            }
        }
        return false;
    }

    private void addStaticImportHints(String member, List<String> owners) {
        for (String imp : imports) {
            if (!imp.endsWith(":static")) {
                continue;
            }
            String target = imp.substring(0, imp.length() - ":static".length());
            if (target.endsWith(".*")) {
                owners.add(target.substring(0, target.length() - 2));
            } else {
                int dot = target.lastIndexOf('.');
                if (dot > 0 && target.substring(dot + 1).equals(member)) {
                    owners.add(target.substring(0, dot));
                }
            }
        }
    }

    private void addStaticOwnerHints(String field, List<String> owners) {
        addStaticImportHints(field, owners);
    }
}
