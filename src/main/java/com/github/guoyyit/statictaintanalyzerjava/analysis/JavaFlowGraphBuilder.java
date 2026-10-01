package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Assembles the whole-program {@link FlowGraph} from {@link FunctionSummary}s.
 *
 * <p>With a {@link ClassModel}, method nodes are
 * {@code qualified.Class#method}, static fields are hoisted into the shared
 * {@code $static} scope, calls are resolved across classes/packages/
 * inheritance/overloading, and aliased objects bind field suffixes across
 * parameter/argument, receiver/this and return/destination edges. A null model
 * selects legacy DSL semantics.
 */
final class JavaFlowGraphBuilder {

    static final String THIS = JavaSummarizer.THIS;
    static final String STATIC = JavaSummarizer.STATIC_SCOPE;

    private final Map<String, FunctionSummary> summaries;
    private final AnalysisRules rules;
    private final ClassModel model;
    private final FlowGraph graph;
    private final Map<TaintEngine.SourceLabel, String> labelOrigin;
    private final List<TaintEngine.SinkPoint> sinkPoints;
    private final boolean java;

    private JavaFlowGraphBuilder(Map<String, FunctionSummary> summaries, AnalysisRules rules,
                                 ClassModel model, FlowGraph graph,
                                 Map<TaintEngine.SourceLabel, String> labelOrigin,
                                 List<TaintEngine.SinkPoint> sinkPoints) {
        this.summaries = summaries;
        this.rules = rules;
        this.model = model;
        this.graph = graph;
        this.labelOrigin = labelOrigin;
        this.sinkPoints = sinkPoints;
        this.java = model != null;
    }

    static void build(Map<String, FunctionSummary> summaries, AnalysisRules rules,
                      ClassModel model, FlowGraph graph,
                      Map<TaintEngine.SourceLabel, String> labelOrigin,
                      List<TaintEngine.SinkPoint> sinkPoints) {
        new JavaFlowGraphBuilder(summaries, rules, model, graph, labelOrigin, sinkPoints).run();
    }

    private void run() {
        registerIntra();
        wireCalls();
        registerSourcesAndSinks();
    }

    // ------------------------------------------------------- node mapping

    private String node(String fn, String variable) {
        if (java && variable != null && variable.startsWith(STATIC + ".")) {
            return FlowGraph.key(STATIC, variable);
        }
        return FlowGraph.key(fn, variable == null ? "" : variable);
    }

    private void register(String fn, String variable, String file) {
        graph.ensureNode(node(fn, variable), file);
    }

    private void edge(String fromFn, String fromVar, String toFn, String toVar,
                      int line, String kind, String file) {
        graph.addNodeEdge(node(fromFn, fromVar), node(toFn, toVar), line, kind, file);
    }

    // ----------------------------------------------------------- intra

    private void registerIntra() {
        for (FunctionSummary fn : summaries.values()) {
            for (String param : fn.params()) {
                register(fn.functionName(), param, fn.file());
            }
            for (FunctionSummary.AssignFact a : fn.assignments()) {
                register(fn.functionName(), a.dst(), fn.file());
                for (String src : a.srcs()) {
                    register(fn.functionName(), src, fn.file());
                    edge(fn.functionName(), src, fn.functionName(), a.dst(),
                            a.line(), FlowGraph.KIND_ASSIGN, fn.file());
                }
            }
            for (FunctionSummary.ReturnFact r : fn.returns()) {
                for (String src : r.srcs()) {
                    register(fn.functionName(), src, fn.file());
                    edge(fn.functionName(), src, fn.functionName(), FlowGraph.RET_VAR,
                            r.line(), FlowGraph.KIND_RETURN, fn.file());
                }
            }
            if (java) {
                for (FunctionSummary.AliasFact alias : fn.aliases()) {
                    register(fn.functionName(), alias.left(), fn.file());
                    register(fn.functionName(), alias.right(), fn.file());
                    edge(fn.functionName(), alias.left(), fn.functionName(), alias.right(),
                            alias.line(), FlowGraph.KIND_ALIAS, fn.file());
                    edge(fn.functionName(), alias.right(), fn.functionName(), alias.left(),
                            alias.line(), FlowGraph.KIND_ALIAS, fn.file());
                    linkAliasSuffixes(fn, alias.left(), alias.right(), alias.line());
                }
            }
        }
    }

    /** Mirrors observed field suffixes between two aliased roots inside one method. */
    private void linkAliasSuffixes(FunctionSummary fn, String leftRoot, String rightRoot, int line) {
        linkSameSuffixes(fn.functionName(), leftRoot, rightRoot, line, fn.file());
    }

    private void linkSameSuffixes(String fnName, String leftRoot, String rightRoot, int line, String file) {
        Set<String> left = new java.util.HashSet<>(suffixes(fnName, leftRoot));
        Set<String> right = new java.util.HashSet<>(suffixes(fnName, rightRoot));
        Set<String> shared = new java.util.HashSet<>(left);
        shared.retainAll(right);
        for (String suffix : shared) {
            edge(fnName, leftRoot + "." + suffix, fnName, rightRoot + "." + suffix,
                    line, FlowGraph.KIND_ALIAS, file);
            edge(fnName, rightRoot + "." + suffix, fnName, leftRoot + "." + suffix,
                    line, FlowGraph.KIND_ALIAS, file);
        }
    }

    // ------------------------------------------------------------ calls

    private record CallView(ClassModel.MethodTarget target,
                            String qualifiedMethod,
                            String qualifiedStatic,
                            String bareName) {
    }

    private void wireCalls() {
        for (FunctionSummary fn : summaries.values()) {
            for (FunctionSummary.CallFact call : fn.calls()) {
                if (java) {
                    CallView view = resolveCall(fn, call);
                    if (isSanitized(view)) {
                        continue;
                    }
                    wireJavaCall(fn, call, view);
                } else {
                    wireDslCall(fn, call);
                }
            }
        }
    }

    private boolean isSanitized(CallView view) {
        for (AnalysisRules.SanitizerRule r : rules.sanitizers()) {
            if (AnalysisRules.matchesJava(r.pattern(),
                    view.qualifiedMethod(), view.qualifiedStatic(), view.bareName())) {
                return true;
            }
        }
        return false;
    }

    private void wireDslCall(FunctionSummary fn, FunctionSummary.CallFact call) {
        FunctionSummary callee = summaries.get(call.callee());
        if (callee != null) {
            int bound = Math.min(call.argVars().size(), callee.params().size());
            for (int i = 0; i < bound; i++) {
                edge(fn.functionName(), call.argVars().get(i),
                        callee.functionName(), callee.params().get(i),
                        call.line(), FlowGraph.KIND_ARG, fn.file());
            }
            if (call.dst() != null) {
                edge(callee.functionName(), FlowGraph.RET_VAR,
                        fn.functionName(), call.dst(),
                        call.line(), FlowGraph.KIND_CALL_RETURN, fn.file());
            }
        } else if (call.dst() != null) {
            for (String argVar : call.argVars()) {
                edge(fn.functionName(), argVar, fn.functionName(), call.dst(),
                        call.line(), FlowGraph.KIND_CALL_RETURN, fn.file());
            }
        }
    }

    private void wireJavaCall(FunctionSummary fn, FunctionSummary.CallFact call, CallView view) {
        FunctionSummary callee = view == null || view.target() == null ? null
                : summaries.get(ClassModel.methodId(view.target().classQualifiedName(),
                        view.target().methodName()));

        if (callee == null) {
            wireUnresolvedJavaCall(fn, call, view);
            return;
        }

        List<String> calleeParams = callee.params();
        int firstParam = 0;
        if (!callee.isStatic()) {
            String receiver = callReceiverVar(fn, call);
            boolean receiverApplies = receiverTargetApplies(fn, call, view);
            if (receiver != null && calleeParams.contains(THIS) && receiverApplies) {
                bindObjects(fn.functionName(), receiver,
                        callee.functionName(), THIS, call.line(), fn.file(), callee.file());
                firstParam = 1;
            }
        }
        int bound = Math.min(call.argVars().size(), calleeParams.size() - firstParam);
        for (int i = 0; i < bound; i++) {
            bindObjects(fn.functionName(), call.argVars().get(i),
                    callee.functionName(), calleeParams.get(firstParam + i),
                    call.line(), fn.file(), callee.file());
        }
        if (call.dst() != null) {
            if (call.newType() != null || !callee.isStatic()) {
                bindObjects(callee.functionName(), FlowGraph.RET_VAR,
                        fn.functionName(), call.dst(), call.line(), callee.file(), fn.file());
            } else {
                edge(callee.functionName(), FlowGraph.RET_VAR,
                        fn.functionName(), call.dst(), call.line(),
                        FlowGraph.KIND_CALL_RETURN, callee.file());
            }
        }
    }

    private String callReceiverVar(FunctionSummary fn, FunctionSummary.CallFact call) {
        if (call.receiverVar() != null) {
            return call.receiverVar();
        }
        if (call.qualifierType() != null) {
            return null;
        }
        return fn.isStatic() ? null : THIS;
    }

    /**
     * Receiver binding is valid only when the invocation was made on a receiver
     * whose type owns the target (instance call on a typed value, or this/super),
     * or an unqualified call resolves inside the caller's own class hierarchy.
     */
    private boolean receiverTargetApplies(FunctionSummary fn, FunctionSummary.CallFact call,
                                          CallView view) {
        if (view.target() == null) {
            return false;
        }
        String targetClass = view.target().classQualifiedName();
        if (call.qualifierType() != null) {
            return true; // static calls never reach here (callee is static)
        }
        if (call.newType() != null) {
            return false;
        }
        if (call.receiverVar() == null) {
            // unqualified call: valid only inside the caller's class hierarchy
            return isSubclass(contextClass(fn), targetClass);
        }
        String receiverType = receiverType(fn, call.receiverVar());
        if (receiverType == null) {
            return false;
        }
        String resolved = model.resolveType(contextClass(fn), receiverType);
        return resolved != null && isSubclass(resolved, targetClass);
    }

    private boolean isSubclass(String subType, String superType) {
        if (subType == null) {
            return false;
        }
        if (subType.equals(superType)) {
            return true;
        }
        if (!model.hasType(subType)) {
            return false;
        }
        for (String sup : model.supertypesOf(subType)) {
            String resolved = model.resolveType(subType, sup);
            if (resolved != null && isSubclass(resolved, superType)) {
                return true;
            }
        }
        return false;
    }

    private CallView resolveCall(FunctionSummary fn, FunctionSummary.CallFact call) {
        String bareName = call.callee();
        boolean isNew = call.newType() != null;
        String methodName = isNew ? JavaSummarizer.INIT : bareName;
        String contextClass = contextClass(fn);

        ClassModel.MethodTarget target;
        String qualifiedStatic = null;
        String qualifiedMethod;

        if (call.qualifierType() != null) {
            target = model.resolveMethod(contextClass, call.qualifierType(), methodName,
                    call.argCount(), true);
            String typeQ = model.resolveType(contextClass, call.qualifierType());
            if (target != null) {
                qualifiedMethod = ClassModel.methodId(target.classQualifiedName(), target.methodName());
                qualifiedStatic = target.classQualifiedName() + "." + bareName; // dotted spelling for globs
            } else {
                String base = typeQ != null ? typeQ : call.qualifierType();
                qualifiedMethod = base + "#" + methodName;
                qualifiedStatic = base + "." + bareName;
            }
        } else if (isNew) {
            target = model.resolveMethod(contextClass, call.newType(), methodName,
                    call.argCount(), true);
            String typeQ = model.resolveType(contextClass, call.newType());
            qualifiedMethod = target != null
                    ? ClassModel.methodId(target.classQualifiedName(), methodName)
                    : (typeQ != null ? typeQ : call.newType()) + "#" + methodName;
        } else {
            String receiverType;
            if (call.receiverVar() != null) {
                receiverType = receiverType(fn, call.receiverVar());
            } else if (fn.isStatic()) {
                receiverType = null; // static context: no implicit this
            } else {
                receiverType = contextClass; // unqualified call -> implicit this
            }
            target = model.resolveMethod(contextClass, receiverType, bareName,
                    call.argCount(), false);
            if (target != null) {
                qualifiedMethod = ClassModel.methodId(target.classQualifiedName(), bareName);
                qualifiedStatic = target.classQualifiedName() + "." + bareName; // dotted spelling for globs
            } else {
                qualifiedMethod = null;
            }
        }
        return new CallView(target, qualifiedMethod, qualifiedStatic, bareName);
    }

    private String contextClass(FunctionSummary fn) {
        return fn.className() == null || fn.className().isEmpty()
                ? fn.functionName() : fn.className();
    }

    /** Light receiver type inference from declared local/parameter types. */
    private String receiverType(FunctionSummary fn, String receiverVar) {
        if (THIS.equals(receiverVar)) {
            return fn.className();
        }
        String[] parts = receiverVar.split("\\.");
        String current = THIS.equals(parts[0]) ? fn.className()
                : resolveDeclaredType(fn, fn.varTypes().get(parts[0]));
        for (int i = 1; i < parts.length && current != null; i++) {
            current = fieldType(fn, current, parts[i]);
        }
        return current;
    }

    /** Resolves a declared (possibly simple) type name in the caller's context. */
    private String resolveDeclaredType(FunctionSummary fn, String type) {
        if (type == null || type.isEmpty()) {
            return type;
        }
        if (type.indexOf('.') >= 0) {
            return type;
        }
        String resolved = model.resolveType(contextClass(fn), type);
        return resolved != null ? resolved : type;
    }

    /** Declared type of {@code fieldName} on {@code ownerType} or one of its supers. */
    private String fieldType(FunctionSummary context, String ownerType, String fieldName) {
        String resolved = model.fieldType(contextClass(context), ownerType, fieldName);
        return resolved == null ? null : resolveDeclaredType(context, resolved);
    }

    private static String stripArray(String type) {
        if (type == null) {
            return null;
        }
        int idx = type.indexOf('[');
        return idx < 0 ? type : type.substring(0, idx);
    }

    /**
     * Binds two object roots across method boundaries in both directions, and
     * mirrors all observed field suffixes so aliased fields stay in sync.
     */
    private void bindObjects(String fromFn, String fromVar, String toFn, String toVar,
                             int line, String fromFile, String toFile) {
        edge(fromFn, fromVar, toFn, toVar, line, FlowGraph.KIND_ARG, fromFile);
        edge(toFn, toVar, fromFn, fromVar, line, FlowGraph.KIND_ARG, toFile);
        Set<String> left = new HashSet<>(suffixes(fromFn, fromVar));
        Set<String> right = new HashSet<>(suffixes(toFn, toVar));
        Set<String> shared = new HashSet<>(left);
        shared.retainAll(right);
        for (String suffix : shared) {
            edge(fromFn, fromVar + "." + suffix, toFn, toVar + "." + suffix,
                    line, FlowGraph.KIND_ALIAS, fromFile);
            edge(toFn, toVar + "." + suffix, fromFn, fromVar + "." + suffix,
                    line, FlowGraph.KIND_ALIAS, toFile);
        }
    }

    private List<String> suffixes(String fn, String root) {
        FunctionSummary s = summaries.get(fn);
        if (s == null) {
            return List.of();
        }
        String prefix = root + ".";
        TreeSet<String> found = new TreeSet<>();
        addSuffixes(s.params(), prefix, found);
        for (FunctionSummary.AssignFact a : s.assignments()) {
            addSuffixes(List.of(a.dst()), prefix, found);
            addSuffixes(a.srcs(), prefix, found);
        }
        for (FunctionSummary.CallFact c : s.calls()) {
            addSuffixes(c.argVars(), prefix, found);
            addSuffixes(c.receiverVar() == null ? List.of() : List.of(c.receiverVar()), prefix, found);
            if (c.dst() != null) {
                addSuffixes(List.of(c.dst()), prefix, found);
            }
        }
        for (FunctionSummary.ReturnFact r : s.returns()) {
            addSuffixes(r.srcs(), prefix, found);
        }
        for (FunctionSummary.AliasFact a : s.aliases()) {
            addSuffixes(List.of(a.left(), a.right()), prefix, found);
        }
        return List.copyOf(found);
    }

    private void addSuffixes(List<String> vars, String prefix, TreeSet<String> out) {
        for (String v : vars) {
            if (v != null && v.startsWith(prefix)) {
                String suffix = v.substring(prefix.length());
                if (!suffix.isEmpty()) {
                    out.add(suffix);
                }
            }
        }
    }

    private void wireUnresolvedJavaCall(FunctionSummary fn, FunctionSummary.CallFact call, CallView view) {
        // If the bare method name exists anywhere in the analyzed project, an
        // unresolved invocation is a binding miss on a real method, not an
        // external identity function: do not conservatively taint through.
        if (view != null && view.bareName() != null && methodExistsInProject(view.bareName())) {
            return;
        }
        if (call.dst() == null) {
            return;
        }
        for (String argVar : call.argVars()) {
            edge(fn.functionName(), argVar, fn.functionName(), call.dst(),
                        call.line(), FlowGraph.KIND_CALL_RETURN, fn.file());
        }
    }

    private boolean methodExistsInProject(String bareName) {
        for (FunctionSummary s : summaries.values()) {
            String fn = s.functionName();
            int hash = fn.indexOf('#');
            String name = hash < 0 ? fn : fn.substring(hash + 1);
            if (name.equals(bareName)) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------- sources / sinks

    private void registerSourcesAndSinks() {
        for (FunctionSummary fn : summaries.values()) {
            for (FunctionSummary.SourceFact s : fn.sources()) {
                register(fn.functionName(), s.dst(), fn.file());
                labelOrigin.put(new TaintEngine.SourceLabel(s.ruleId(), fn.file(), s.line()),
                        node(fn.functionName(), s.dst()));
            }
            for (FunctionSummary.SinkFact s : fn.sinks()) {
                addDslSink(fn, s);
            }
        }
        if (java) {
            registerJavaRules();
        }
    }

    private void addDslSink(FunctionSummary fn, FunctionSummary.SinkFact s) {
        String sinkVar = "$sink:" + s.line() + ":" + s.ruleId();
        register(fn.functionName(), sinkVar, fn.file());
        for (String argVar : s.argVars()) {
            register(fn.functionName(), argVar, fn.file());
            edge(fn.functionName(), argVar, fn.functionName(), sinkVar, s.line(),
                    FlowGraph.KIND_SINK, fn.file());
        }
        sinkPoints.add(new TaintEngine.SinkPoint(node(fn.functionName(), sinkVar),
                s.ruleId(), fn.functionName(), fn.className(), fn.file(), s.line()));
    }

    private void registerJavaRules() {
        for (FunctionSummary fn : summaries.values()) {
            for (FunctionSummary.CallFact call : fn.calls()) {
                CallView view = resolveCall(fn, call);
                String qm = view.qualifiedMethod();
                String qs = view.qualifiedStatic();
                String bare = view.bareName();

                AnalysisRules.SanitizerRule sanitizer = firstSanitizer(qm, qs, bare);
                if (sanitizer != null) {
                    continue; // taint cut: no call edges are emitted at all
                }

                AnalysisRules.SourceRule source = firstSource(qm, qs, bare);
                if (source != null && call.dst() != null) {
                    String originNode = node(fn.functionName(), call.dst());
                    graph.ensureNode(originNode, fn.file());
                    TaintEngine.SourceLabel label =
                            new TaintEngine.SourceLabel(source.id(), fn.file(), call.line());
                    labelOrigin.putIfAbsent(label, originNode);
                }

                AnalysisRules.SinkRule sink = firstSink(qm, qs, bare);
                if (sink != null) {
                    addResolvedSink(fn, call, view, sink);
                }
            }
        }
    }

    private final Set<String> createdSinks = new HashSet<>();

    /**
     * A resolved sink creates one sink node per call site, but the exposing
     * edges originate at the callee's formal parameters, so every reconstructed
     * path traverses the real callee class/method before reaching the sink.
     */
    private void addResolvedSink(FunctionSummary caller, FunctionSummary.CallFact call,
                                 CallView view, AnalysisRules.SinkRule sink) {
        FunctionSummary callee = view.target() == null ? null
                : summaries.get(ClassModel.methodId(view.target().classQualifiedName(),
                        view.target().methodName()));
        if (callee == null) {
            // Unresolved (e.g. library) sink: expose at the call site directly.
            String sinkVar = "$sink:" + call.line() + ":" + sink.id();
            register(caller.functionName(), sinkVar, caller.file());
            for (String argVar : call.argVars()) {
                edge(caller.functionName(), argVar, caller.functionName(), sinkVar,
                        call.line(), FlowGraph.KIND_SINK, caller.file());
            }
            sinkPoints.add(new TaintEngine.SinkPoint(node(caller.functionName(), sinkVar),
                    sink.id(), caller.functionName(), caller.className(), caller.file(), call.line()));
            return;
        }
        String siteSeq = call.callSiteId();
        int colon = siteSeq.lastIndexOf(':');
        siteSeq = colon < 0 ? "0" : siteSeq.substring(colon + 1);
        String sinkVar = "$sink:" + call.line() + ":" + siteSeq + ":" + sink.id();
        String sinkNode = node(caller.functionName(), sinkVar);
        if (!createdSinks.add(sinkNode)) {
            return;
        }
        graph.ensureNode(sinkNode, caller.file());
        List<String> params = callee.params();
        int firstParam = callee.isStatic() ? 0 : 1;
        for (int i = firstParam; i < params.size(); i++) {
            edge(callee.functionName(), params.get(i), caller.functionName(), sinkVar,
                    call.line(), FlowGraph.KIND_SINK, callee.file());
        }
        sinkPoints.add(new TaintEngine.SinkPoint(sinkNode, sink.id(),
                caller.functionName(), caller.className(), caller.file(), call.line()));
    }

    private AnalysisRules.SourceRule firstSource(String qm, String qs, String bare) {
        for (AnalysisRules.SourceRule r : rules.sources()) {
            if (AnalysisRules.matchesJava(r.pattern(), qm, qs, bare)) {
                return r;
            }
        }
        return null;
    }

    private AnalysisRules.SinkRule firstSink(String qm, String qs, String bare) {
        for (AnalysisRules.SinkRule r : rules.sinks()) {
            if (AnalysisRules.matchesJava(r.pattern(), qm, qs, bare)) {
                return r;
            }
        }
        return null;
    }

    private AnalysisRules.SanitizerRule firstSanitizer(String qm, String qs, String bare) {
        for (AnalysisRules.SanitizerRule r : rules.sanitizers()) {
            if (AnalysisRules.matchesJava(r.pattern(), qm, qs, bare)) {
                return r;
            }
        }
        return null;
    }
}
