package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.analysis.model.MethodModel;
import com.github.guoyyit.statictaintanalyzerjava.analysis.model.MethodSummary;
import com.github.guoyyit.statictaintanalyzerjava.analysis.model.ProgramModel;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.domain.RuleSet;
import com.github.guoyyit.statictaintanalyzerjava.domain.SourceLocation;
import com.github.guoyyit.statictaintanalyzerjava.domain.TaintRule;
import com.github.guoyyit.statictaintanalyzerjava.domain.TaintStep;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.ArrayAccessExpr;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.InstanceOfExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SwitchExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.AssertStmt;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.DoStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.LabeledStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchStmt;
import com.github.javaparser.ast.stmt.SynchronizedStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.github.javaparser.ast.stmt.YieldStmt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Inter-procedural taint engine.
 *
 * <p>Phase A computes a qualitative {@link MethodSummary} per method by bounded
 * fixpoint over the call graph (params are seeded with symbolic taint). Phase B
 * replays the program with concrete taint, converges field taint by bounded
 * fixpoint and emits {@link Finding}s at sink call sites. Loops are handled by
 * re-walking method bodies until a fixpoint (capped), recursion by the summary
 * fixpoint (capped), and aliases by assignment/mutator propagation; every bound
 * is explicit so results are finite and deterministic.
 */
public final class TaintEngine {

    /** Outcome of an engine run: findings plus the summaries used for incremental reuse. */
    public record Result(List<Finding> findings, Map<String, MethodSummary> summaries) {
    }

    private static final int MAX_SUMMARY_ROUNDS = 32;
    private static final int MAX_METHOD_PASSES = 8;
    private static final int MAX_FIELD_ROUNDS = 8;
    private static final String PARAM_PREFIX = "__param";

    /** Methods known to mutate their receiver with tainted arguments. */
    private static final Set<String> MUTATOR_METHODS = Set.of(
            "append", "insert", "put", "add", "set", "putAll", "addAll",
            "write", "print", "println", "format", "replace");

    private final ProgramModel model;
    private final RuleSet rules;

    public TaintEngine(ProgramModel model, RuleSet rules) {
        this.model = model;
        this.rules = rules;
    }

    /** Full analysis of every method in the program. */
    public Result analyzeAll(long version) {
        Set<String> all = new TreeSet<>();
        for (MethodModel m : model.methods()) {
            all.add(m.signature());
        }
        return analyze(all, Map.of(), List.of(), version);
    }

    /**
     * Analysis bounded to {@code affectedMethods}; summaries and findings of
     * unaffected methods are reused from the last committed snapshot.
     */
    public Result analyze(Set<String> affectedMethods,
                          Map<String, MethodSummary> priorSummaries,
                          List<Finding> priorFindings,
                          long version) {
        Set<String> affected = new TreeSet<>(affectedMethods);

        // ---- Phase A: summary fixpoint (only affected methods are recomputed) ----
        Map<String, MethodSummary> seed = new TreeMap<>();
        priorSummaries.forEach((sig, s) -> {
            if (!affected.contains(sig)) {
                seed.put(sig, s);
            }
        });
        for (String sig : affected) {
            if (model.bySignature(sig) != null) {
                seed.put(sig, MethodSummary.empty(sig));
            }
        }
        Map<String, MethodSummary> summaries = seed;
        for (int round = 0; round < MAX_SUMMARY_ROUNDS; round++) {
            Map<String, MethodSummary> next = new TreeMap<>(summaries);
            for (String sig : affected) {
                MethodModel m = model.bySignature(sig);
                if (m != null) {
                    next.put(sig, computeSummary(m, summaries));
                }
            }
            if (next.equals(summaries)) {
                summaries = next;
                break;
            }
            summaries = next;
        }

        // ---- Phase B: concrete field-taint fixpoint over all methods ----
        Map<String, TaintValue> fieldTaint = new TreeMap<>();
        for (int round = 0; round < MAX_FIELD_ROUNDS; round++) {
            Map<String, TaintValue> next = new TreeMap<>(fieldTaint);
            for (MethodModel m : model.methods()) {
                walkMethod(m, SeedMode.CONCRETE, summaries, fieldTaint, next, null, version);
            }
            if (next.equals(fieldTaint)) {
                fieldTaint = next;
                break;
            }
            fieldTaint = next;
        }

        // ---- Final pass: emit findings for affected methods only ----
        List<Finding> findings = new ArrayList<>();
        Map<String, TaintValue> finalFields = new TreeMap<>(fieldTaint);
        for (MethodModel m : model.methods()) {
            List<Finding> sink = affected.contains(m.signature()) ? findings : null;
            walkMethod(m, SeedMode.CONCRETE, summaries, finalFields, finalFields, sink, version);
        }
        for (Finding f : priorFindings) {
            if (!affected.contains(f.sinkMethodSignature())) {
                findings.add(f);
            }
        }
        return new Result(Finding.dedupAndSort(findings), summaries);
    }

    // ------------------------------------------------------------------
    // Phase A: qualitative summary
    // ------------------------------------------------------------------

    private MethodSummary computeSummary(MethodModel method, Map<String, MethodSummary> summaries) {
        WalkContext ctx = newContext(method, SeedMode.SUMMARY, summaries,
                new TreeMap<>(), new TreeMap<>(), null, 0L);
        runPasses(ctx);
        Set<Integer> taintedParams = new TreeSet<>();
        String returnSource = "";
        for (String id : new TreeSet<>(ctx.returnTaint.sourceRuleIds())) {
            if (id.startsWith(PARAM_PREFIX)) {
                taintedParams.add(Integer.parseInt(id.substring(PARAM_PREFIX.length())));
            } else if (returnSource.isEmpty()) {
                returnSource = id;
            }
        }
        return new MethodSummary(method.signature(), taintedParams, returnSource, ctx.taintedFieldsWritten);
    }

    // ------------------------------------------------------------------
    // Method walking
    // ------------------------------------------------------------------

    private enum SeedMode {SUMMARY, CONCRETE}

    private void walkMethod(MethodModel method, SeedMode mode,
                            Map<String, MethodSummary> summaries,
                            Map<String, TaintValue> fieldRead,
                            Map<String, TaintValue> fieldWrite,
                            List<Finding> findings, long version) {
        WalkContext ctx = newContext(method, mode, summaries, fieldRead, fieldWrite, findings, version);
        runPasses(ctx);
    }

    private WalkContext newContext(MethodModel method, SeedMode mode,
                                   Map<String, MethodSummary> summaries,
                                   Map<String, TaintValue> fieldRead,
                                   Map<String, TaintValue> fieldWrite,
                                   List<Finding> findings, long version) {
        WalkContext ctx = new WalkContext();
        ctx.method = method;
        ctx.summaries = summaries;
        ctx.fieldTaintRead = fieldRead;
        ctx.fieldTaintWrite = fieldWrite;
        ctx.findings = findings;
        ctx.version = version;
        // Type environment: params, then fields of the enclosing class.
        for (int i = 0; i < method.paramNames().size(); i++) {
            ctx.typeEnv.put(method.paramNames().get(i), method.paramTypes().get(i));
        }
        model.fieldTypesOf(method.className()).forEach((n, t) -> ctx.typeEnv.putIfAbsent(n, t));
        // Seed parameter taint.
        for (int i = 0; i < method.paramNames().size(); i++) {
            String name = method.paramNames().get(i);
            if (mode == SeedMode.SUMMARY) {
                ctx.env.put(name, TaintValue.fromSource(PARAM_PREFIX + i,
                        step(method.declaration(), method, "parameter " + name)));
            } else {
                Optional<TaintRule> paramSource = rules.sources().stream()
                        .filter(r -> r.matchesSignature(method.className(), method.methodName()))
                        .findFirst();
                if (paramSource.isPresent()) {
                    ctx.env.put(name, TaintValue.fromSource(paramSource.get().id(),
                            step(method.declaration(), method,
                                    "source " + paramSource.get().id() + " on parameter " + name)));
                }
            }
        }
        return ctx;
    }

    /** Re-walks the body until env/return/field-writes stabilize (bounded). */
    private void runPasses(WalkContext ctx) {
        MethodDeclaration md = ctx.method.declaration();
        if (md.getBody().isEmpty()) {
            return;
        }
        Map<String, TaintValue> prevEnv = Map.of();
        TaintValue prevReturn = TaintValue.clean();
        Set<String> prevFields = Set.of();
        for (int pass = 0; pass < MAX_METHOD_PASSES; pass++) {
            ctx.passFieldWrites = new TreeMap<>();
            walkStatement(md.getBody().get(), ctx);
            boolean stable = ctx.env.equals(prevEnv)
                    && ctx.returnTaint.equals(prevReturn)
                    && ctx.passFieldWrites.keySet().equals(prevFields)
                    && pass > 0;
            prevEnv = new TreeMap<>(ctx.env);
            prevReturn = ctx.returnTaint;
            prevFields = ctx.passFieldWrites.keySet();
            if (stable) {
                break;
            }
        }
    }

    private void walkStatement(Statement stmt, WalkContext ctx) {
        if (stmt instanceof BlockStmt block) {
            block.getStatements().forEach(s -> walkStatement(s, ctx));
        } else if (stmt instanceof ExpressionStmt exprStmt) {
            evalExpr(exprStmt.getExpression(), ctx);
        } else if (stmt instanceof ReturnStmt ret) {
            ret.getExpression().ifPresent(e ->
                    ctx.returnTaint = ctx.returnTaint.merge(evalExpr(e, ctx)));
        } else if (stmt instanceof IfStmt ifStmt) {
            evalExpr(ifStmt.getCondition(), ctx);
            walkStatement(ifStmt.getThenStmt(), ctx);
            ifStmt.getElseStmt().ifPresent(e -> walkStatement(e, ctx));
        } else if (stmt instanceof ForStmt forStmt) {
            forStmt.getInitialization().forEach(e -> evalExpr(e, ctx));
            forStmt.getCompare().ifPresent(c -> evalExpr(c, ctx));
            walkStatement(forStmt.getBody(), ctx);
            forStmt.getUpdate().forEach(e -> evalExpr(e, ctx));
        } else if (stmt instanceof ForEachStmt forEach) {
            TaintValue iterable = evalExpr(forEach.getIterable(), ctx);
            VariableDeclarator var = forEach.getVariable().getVariables().get(0);
            ctx.typeEnv.putIfAbsent(var.getNameAsString(), var.getTypeAsString());
            assignVar(var.getNameAsString(), iterable, forEach, ctx);
            walkStatement(forEach.getBody(), ctx);
        } else if (stmt instanceof WhileStmt whileStmt) {
            evalExpr(whileStmt.getCondition(), ctx);
            walkStatement(whileStmt.getBody(), ctx);
        } else if (stmt instanceof DoStmt doStmt) {
            walkStatement(doStmt.getBody(), ctx);
            evalExpr(doStmt.getCondition(), ctx);
        } else if (stmt instanceof SwitchStmt switchStmt) {
            evalExpr(switchStmt.getSelector(), ctx);
            switchStmt.getEntries().forEach(e ->
                    e.getStatements().forEach(s -> walkStatement(s, ctx)));
        } else if (stmt instanceof TryStmt tryStmt) {
            tryStmt.getResources().forEach(r -> evalExpr(r, ctx));
            walkStatement(tryStmt.getTryBlock(), ctx);
            tryStmt.getCatchClauses().forEach(c -> walkStatement(c.getBody(), ctx));
            tryStmt.getFinallyBlock().ifPresent(f -> walkStatement(f, ctx));
        } else if (stmt instanceof SynchronizedStmt sync) {
            evalExpr(sync.getExpression(), ctx);
            walkStatement(sync.getBody(), ctx);
        } else if (stmt instanceof LabeledStmt labeled) {
            walkStatement(labeled.getStatement(), ctx);
        } else if (stmt instanceof ThrowStmt throwStmt) {
            evalExpr(throwStmt.getExpression(), ctx);
        } else if (stmt instanceof AssertStmt assertStmt) {
            evalExpr(assertStmt.getCheck(), ctx);
            assertStmt.getMessage().ifPresent(m -> evalExpr(m, ctx));
        } else if (stmt instanceof YieldStmt yield) {
            ctx.returnTaint = ctx.returnTaint.merge(evalExpr(yield.getExpression(), ctx));
        }
        // Break/continue/empty/local class declarations: no taint effect.
    }

    // ------------------------------------------------------------------
    // Expression evaluation
    // ------------------------------------------------------------------

    private TaintValue evalExpr(Expression expr, WalkContext ctx) {
        if (expr == null) {
            return TaintValue.clean();
        }
        if (expr instanceof LiteralExpr || expr instanceof ThisExpr
                || expr instanceof com.github.javaparser.ast.expr.ClassExpr
                || expr instanceof com.github.javaparser.ast.expr.MethodReferenceExpr) {
            return TaintValue.clean();
        }
        if (expr instanceof NameExpr name) {
            return lookupVar(name.getNameAsString(), ctx);
        }
        if (expr instanceof FieldAccessExpr access) {
            return lookupField(resolveFieldKey(access, ctx), ctx);
        }
        if (expr instanceof AssignExpr assign) {
            return evalAssign(assign, ctx);
        }
        if (expr instanceof VariableDeclarationExpr decl) {
            TaintValue result = TaintValue.clean();
            for (VariableDeclarator var : decl.getVariables()) {
                ctx.typeEnv.putIfAbsent(var.getNameAsString(), var.getTypeAsString());
                TaintValue init = var.getInitializer().map(e -> evalExpr(e, ctx))
                        .orElse(TaintValue.clean());
                assignVar(var.getNameAsString(), init, var, ctx);
                result = init;
            }
            return result;
        }
        if (expr instanceof MethodCallExpr call) {
            return evalCall(call, ctx);
        }
        if (expr instanceof BinaryExpr binary) {
            return evalExpr(binary.getLeft(), ctx).merge(evalExpr(binary.getRight(), ctx));
        }
        if (expr instanceof ConditionalExpr cond) {
            evalExpr(cond.getCondition(), ctx);
            return evalExpr(cond.getThenExpr(), ctx).merge(evalExpr(cond.getElseExpr(), ctx));
        }
        if (expr instanceof CastExpr cast) {
            return evalExpr(cast.getExpression(), ctx);
        }
        if (expr instanceof EnclosedExpr enclosed) {
            return evalExpr(enclosed.getInner(), ctx);
        }
        if (expr instanceof UnaryExpr unary) {
            return evalExpr(unary.getExpression(), ctx);
        }
        if (expr instanceof ObjectCreationExpr creation) {
            TaintValue t = TaintValue.clean();
            for (Expression arg : creation.getArguments()) {
                t = t.merge(evalExpr(arg, ctx));
            }
            return t;
        }
        if (expr instanceof ArrayAccessExpr access) {
            evalExpr(access.getIndex(), ctx);
            return evalExpr(access.getName(), ctx);
        }
        if (expr instanceof ArrayCreationExpr creation) {
            TaintValue t = TaintValue.clean();
            if (creation.getInitializer().isPresent()) {
                for (Expression v : creation.getInitializer().get().getValues()) {
                    t = t.merge(evalExpr(v, ctx));
                }
            }
            return t;
        }
        if (expr instanceof LambdaExpr lambda) {
            walkStatement(lambda.getBody(), ctx);
            return TaintValue.clean();
        }
        if (expr instanceof SwitchExpr switchExpr) {
            evalExpr(switchExpr.getSelector(), ctx);
            TaintValue t = TaintValue.clean();
            switchExpr.getEntries().forEach(e -> e.getStatements()
                    .forEach(s -> walkStatement(s, ctx)));
            return t;
        }
        if (expr instanceof InstanceOfExpr instanceOf) {
            return evalExpr(instanceOf.getExpression(), ctx);
        }
        return TaintValue.clean();
    }

    private TaintValue evalAssign(AssignExpr assign, WalkContext ctx) {
        TaintValue value = evalExpr(assign.getValue(), ctx);
        Expression target = assign.getTarget();
        if (assign.getOperator() != AssignExpr.Operator.ASSIGN) {
            // Compound assignment keeps the old value too.
            value = evalExpr(target, ctx).merge(value);
        }
        if (target instanceof NameExpr name) {
            assignVar(name.getNameAsString(), value, assign, ctx);
        } else if (target instanceof FieldAccessExpr access) {
            String key = resolveFieldKey(access, ctx);
            writeField(key, value, assign, ctx);
        } else if (target instanceof ArrayAccessExpr array) {
            if (array.getName() instanceof NameExpr name) {
                TaintValue merged = lookupVar(name.getNameAsString(), ctx).merge(value);
                assignVar(name.getNameAsString(), merged, assign, ctx);
            }
        }
        return value;
    }

    private TaintValue evalCall(MethodCallExpr call, WalkContext ctx) {
        String methodName = call.getNameAsString();
        List<TaintValue> argTaints = new ArrayList<>();
        for (Expression arg : call.getArguments()) {
            argTaints.add(evalExpr(arg, ctx));
        }
        TaintValue receiverTaint = call.getScope().map(s -> evalExpr(s, ctx)).orElse(TaintValue.clean());
        String receiverType = call.getScope().map(s -> resolveScopeType(s, ctx)).orElse(ctx.method.className());
        String receiverVar = call.getScope().filter(s -> s instanceof NameExpr)
                .map(s -> ((NameExpr) s).getNameAsString()).orElse(null);

        // Sanitizer: kills taint on the result.
        Optional<TaintRule> sanitizer = rules.matchSanitizer(receiverType, methodName);
        if (sanitizer.isPresent()) {
            return TaintValue.clean();
        }

        // Sink: report tainted arguments / receiver.
        Optional<TaintRule> sink = rules.matchSink(receiverType, methodName);
        if (sink.isPresent()) {
            TaintValue atSink = receiverTaint;
            for (TaintValue t : argTaints) {
                atSink = atSink.merge(t);
            }
            if (atSink.isTainted() && ctx.findings != null) {
                emitFinding(sink.get(), atSink, call, ctx);
            }
        }

        // Source: return value becomes tainted.
        Optional<TaintRule> source = rules.matchSource(receiverType, methodName);
        TaintValue result;
        if (source.isPresent()) {
            result = TaintValue.fromSource(source.get().id(),
                    step(call, ctx.method, "source " + source.get().id() + " via " + methodName));
        } else {
            result = TaintValue.clean();
        }

        // Known methods: apply summaries; unknown: conservative propagator.
        List<MethodModel> candidates = model.byName(methodName).stream()
                .filter(c -> c.arity() == call.getArguments().size())
                .toList();
        if (!candidates.isEmpty()) {
            for (MethodModel callee : candidates) {
                MethodSummary summary = ctx.summaries.get(callee.signature());
                if (summary == null) {
                    continue;
                }
                for (int idx : summary.taintedParamIndexes()) {
                    if (idx < argTaints.size() && argTaints.get(idx).isTainted()) {
                        result = result.merge(argTaints.get(idx).withStep(
                                step(call, ctx.method, "through call " + callee.signature())));
                    }
                }
                if (!summary.returnTaintedBySourceRuleId().isEmpty()) {
                    result = result.merge(TaintValue.fromSource(summary.returnTaintedBySourceRuleId(),
                            step(call, ctx.method, "source " + summary.returnTaintedBySourceRuleId()
                                    + " returned from " + callee.signature())));
                }
            }
        } else {
            for (TaintValue t : argTaints) {
                result = result.merge(t);
            }
            result = result.merge(receiverTaint);
            if (receiverVar != null && MUTATOR_METHODS.contains(methodName)) {
                TaintValue toReceiver = TaintValue.clean();
                for (TaintValue t : argTaints) {
                    toReceiver = toReceiver.merge(t);
                }
                if (toReceiver.isTainted()) {
                    TaintValue merged = lookupVar(receiverVar, ctx).merge(toReceiver)
                            .withStep(step(call, ctx.method, "mutates " + receiverVar + " via " + methodName));
                    ctx.env.put(receiverVar, merged);
                }
            }
        }
        return result;
    }

    private void emitFinding(TaintRule sinkRule, TaintValue taint, MethodCallExpr call, WalkContext ctx) {
        TaintStep sinkStep = step(call, ctx.method, "sink " + sinkRule.id() + " via " + call.getNameAsString());
        SourceLocation sinkLoc = location(call, ctx.method);
        for (String sourceId : new TreeSet<>(taint.sourceRuleIds())) {
            if (sourceId.startsWith(PARAM_PREFIX)) {
                continue; // summary-mode pseudo taint never becomes a finding
            }
            List<TaintStep> path = new ArrayList<>(taint.steps());
            path.add(sinkStep);
            ctx.findings.add(Finding.create(sinkRule.id(), sourceId, sinkRule.risk(), path,
                    sinkLoc, ctx.method.signature(), rules.hash(), ctx.version));
        }
    }

    // ------------------------------------------------------------------
    // Variable / field helpers
    // ------------------------------------------------------------------

    private TaintValue lookupVar(String name, WalkContext ctx) {
        TaintValue t = ctx.env.get(name);
        if (t != null) {
            return t;
        }
        if (ctx.typeEnv.containsKey(name)
                && model.fieldTypesOf(ctx.method.className()).containsKey(name)) {
            return lookupField(ctx.method.className() + "." + name, ctx);
        }
        return TaintValue.clean();
    }

    private TaintValue lookupField(String key, WalkContext ctx) {
        return ctx.fieldTaintRead.getOrDefault(key, TaintValue.clean());
    }

    private void assignVar(String name, TaintValue taint, Node node, WalkContext ctx) {
        if (model.fieldTypesOf(ctx.method.className()).containsKey(name) && !ctx.env.containsKey(name)
                && !ctx.method.paramNames().contains(name) && !isLocal(ctx, name)) {
            writeField(ctx.method.className() + "." + name, taint, node, ctx);
            return;
        }
        ctx.env.put(name, taint.withStep(step(node, ctx.method, "assigned to " + name)));
    }

    private boolean isLocal(WalkContext ctx, String name) {
        return ctx.method.declaration().findAll(VariableDeclarator.class).stream()
                .anyMatch(v -> v.getNameAsString().equals(name));
    }

    private void writeField(String key, TaintValue taint, Node node, WalkContext ctx) {
        if (!taint.isTainted()) {
            return;
        }
        ctx.taintedFieldsWritten.add(key);
        TaintValue withStep = taint.withStep(step(node, ctx.method, "stored to field " + key));
        ctx.fieldTaintWrite.merge(key, withStep, TaintValue::merge);
        ctx.passFieldWrites.merge(key, withStep, TaintValue::merge);
    }

    private String resolveFieldKey(FieldAccessExpr access, WalkContext ctx) {
        String field = access.getNameAsString();
        if (access.getScope() instanceof ThisExpr) {
            return ctx.method.className() + "." + field;
        }
        String scopeType = resolveScopeType(access.getScope(), ctx);
        if (!scopeType.isEmpty()) {
            return scopeType + "." + field;
        }
        return ctx.method.className() + "." + field;
    }

    private String resolveScopeType(Expression scope, WalkContext ctx) {
        if (scope instanceof NameExpr name) {
            String type = ctx.typeEnv.get(name.getNameAsString());
            if (type != null) {
                return model.resolveClassName(type);
            }
            // Static call on a type name, e.g. StringEscapeUtils.escapeSql(x).
            String n = name.getNameAsString();
            if (!n.isEmpty() && Character.isUpperCase(n.charAt(0))) {
                return model.resolveClassName(n);
            }
            return "";
        }
        if (scope instanceof FieldAccessExpr fa) {
            return model.resolveClassName(ctx.typeEnv.getOrDefault(fa.getNameAsString(), ""));
        }
        if (scope instanceof ThisExpr) {
            return ctx.method.className();
        }
        if (scope instanceof ObjectCreationExpr creation) {
            return model.resolveClassName(creation.getTypeAsString());
        }
        if (scope instanceof CastExpr cast) {
            return model.resolveClassName(cast.getTypeAsString());
        }
        return "";
    }

    private SourceLocation location(Node node, MethodModel method) {
        int line = node.getBegin().map(p -> p.line).orElse(0);
        int col = node.getBegin().map(p -> p.column).orElse(0);
        return new SourceLocation(method.file(), line, col, method.signature());
    }

    private TaintStep step(Node node, MethodModel method, String description) {
        return new TaintStep(location(node, method), description);
    }

    /** Per-method walk state. */
    private static final class WalkContext {
        MethodModel method;
        Map<String, TaintValue> env = new TreeMap<>();
        Map<String, String> typeEnv = new TreeMap<>();
        Map<String, MethodSummary> summaries;
        Map<String, TaintValue> fieldTaintRead;
        Map<String, TaintValue> fieldTaintWrite;
        Map<String, TaintValue> passFieldWrites = new TreeMap<>();
        TaintValue returnTaint = TaintValue.clean();
        Set<String> taintedFieldsWritten = new TreeSet<>();
        List<Finding> findings;
        long version;
    }
}
