package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Assembles the whole-program taint graph for Java members.
 *
 * <ul>
 *   <li>method nodes are the member keys ({@code pkg.C#m(sig)}), with a synthetic
 *       {@code $this} first parameter for instance members and {@code $ret};</li>
 *   <li>fields are global nodes {@code field:owner#name} shared across aliases;</li>
 *   <li>calls are resolved structurally via {@link ClassIndex} (imports, same
 *       package, inheritance, overload arity); unresolved calls conservatively
 *       pass argument/receiver taint to the result;</li>
 *   <li>rules classify call sites using both simple and fully qualified tokens,
 *       so FQN and wildcard-prefix patterns work on Java calls;</li>
 *   <li>sources are labeled per call site; sinks are per (site, rule).</li>
 * </ul>
 */
final class JavaGraphBuilder {

    private JavaGraphBuilder() {
    }

    private record SinkSpec(String var, String ruleId, int line) {
    }

    static void build(List<FunctionSummary> members, ClassIndex index, AnalysisRules rules,
                      FlowGraph graph, Map<TaintEngine.SourceLabel, String> labelOrigin,
                      List<TaintEngine.SinkPoint> sinkPoints) {
        // deterministic iteration
        List<FunctionSummary> sorted = new ArrayList<>(members);
        sorted.sort((a, b) -> a.functionName().compareTo(b.functionName()));

        // register member nodes and intra-member edges
        for (FunctionSummary fn : sorted) {
            registerMember(graph, fn);
            for (FunctionSummary.AssignFact a : fn.assignments()) {
                for (String src : a.srcs()) {
                    addEdge(graph, fn, src, a.dst(), a.line(), FlowGraph.KIND_ASSIGN);
                }
            }
            for (FunctionSummary.ReturnFact r : fn.returns()) {
                for (String src : r.srcs()) {
                    addEdge(graph, fn, src, FlowGraph.RET_VAR, r.line(), FlowGraph.KIND_RETURN);
                }
            }
        }

        // field reads lowered to temps
        for (FunctionSummary fn : sorted) {
            for (FunctionSummary.FieldReadFact r : fn.fieldReads()) {
                List<String> owners = index.resolveFieldOwners(r.field(), r.ownerTokens(), fn);
                owners = index.expandFieldOwners(owners);
                for (String owner : owners) {
                    String fieldNode = fieldNode(owner, r.field());
                    registerField(graph, owner, r.field(), fn.file());
                    addEdgeRaw(graph, fieldNode, FlowGraph.key(fn.functionName(), r.temp()),
                            r.line(), FlowGraph.KIND_FIELD_READ, fn, r.field());
                }
                registerLocal(graph, fn, r.temp());
            }
        }
        // field writes
        for (FunctionSummary fn : sorted) {
            for (FunctionSummary.FieldWriteFact w : fn.fieldWrites()) {
                List<String> owners = index.resolveFieldOwners(w.field(), w.ownerTokens(), fn);
                owners = index.expandFieldOwners(owners);
                for (String owner : owners) {
                    String fieldNode = fieldNode(owner, w.field());
                    registerField(graph, owner, w.field(), fn.file());
                    for (String src : w.srcs()) {
                        addEdgeRaw(graph, FlowGraph.key(fn.functionName(), src), fieldNode,
                                w.line(), FlowGraph.KIND_FIELD_WRITE, fn, w.field());
                    }
                }
            }
        }

        // calls
        for (FunctionSummary fn : sorted) {
            for (FunctionSummary.CallFact call : fn.calls()) {
                buildCall(fn, call, index, rules, graph, labelOrigin, sinkPoints);
            }
        }
    }

    private static void buildCall(FunctionSummary fn, FunctionSummary.CallFact call, ClassIndex index,
                                  AnalysisRules rules, FlowGraph graph,
                                  Map<TaintEngine.SourceLabel, String> labelOrigin,
                                  List<TaintEngine.SinkPoint> sinkPoints) {
        FunctionSummary.JavaCall jc = call.javaCall();
        List<String> args = call.argVars();
        List<String> tokens = calleeTokens(fn, call, index);

        // sanitizer first: cuts every flow at this site
        if (rules.isSanitizer(tokens)) {
            return;
        }

        List<FunctionSummary> targets = index.resolveMethods(call.callee(), jc.ownerTokens(),
                args.size(), fn);
        int line = call.line();
        if (targets.isEmpty()) {
            // Unresolved external call: conservatively propagate args + receiver
            // taint to the destination, matching the DSL's unknown-callee policy.
            if (call.dst() != null) {
                for (String arg : args) {
                    addEdge(graph, fn, arg, call.dst(), line, FlowGraph.KIND_CALL_RETURN);
                }
                for (String receiver : jc.receiverVars()) {
                    addEdge(graph, fn, receiver, call.dst(), line, FlowGraph.KIND_CALL_RETURN);
                }
                registerLocal(graph, fn, call.dst());
            }
        } else {
            for (FunctionSummary target : targets) {
                bindCall(fn, target, call, args, graph, line);
            }
        }

        // sources inject taint at the destination / args (constructors taint new object)
        AnalysisRules.SourceRule source = rules.matchSource(tokens);
        if (source != null) {
            String dst = call.dst();
            if (dst == null) {
                dst = "$src:" + Math.floorMod(call.callSiteId().hashCode(), 1 << 20);
                registerLocal(graph, fn, dst);
            }
            registerLocal(graph, fn, dst);
            TaintEngine.SourceLabel label = new TaintEngine.SourceLabel(source.id(), fn.file(), line,
                    call.callSiteId());
            labelOrigin.put(label, FlowGraph.key(fn.functionName(), dst));
        }
        // sinks expose their arguments
        AnalysisRules.SinkRule sink = rules.matchSink(tokens);
        if (sink != null) {
            String sinkVar = "$sink:" + line + ":" + sink.id() + ":"
                    + Math.floorMod(call.callSiteId().hashCode(), 1 << 20);
            registerLocal(graph, fn, sinkVar);
            for (String arg : args) {
                addEdge(graph, fn, arg, sinkVar, line, FlowGraph.KIND_SINK);
            }
            sinkPoints.add(new TaintEngine.SinkPoint(FlowGraph.key(fn.functionName(), sinkVar),
                    sink.id(), fn.functionName(), fn.file(), line));
        }
    }

    private static void bindCall(FunctionSummary fn, FunctionSummary target,
                                 FunctionSummary.CallFact call, List<String> args,
                                 FlowGraph graph, int line) {
        FunctionSummary.JavaCall jc = call.javaCall();
        // instance members: $this occupies parameter 0
        int paramOffset = target.instance() ? 1 : 0;
        int bindable = Math.min(args.size(), target.params().size() - paramOffset);
        for (int i = 0; i < bindable; i++) {
            addEdgeRaw(graph, FlowGraph.key(fn.functionName(), args.get(i)),
                    FlowGraph.key(target.functionName(), target.params().get(i + paramOffset)),
                    line, FlowGraph.KIND_ARG, target, target.params().get(i + paramOffset));
        }
        // receiver taint flows into $this for instance methods/constructors
        if (target.instance()) {
            String thisParam = target.params().get(0);
            if (jc.isConstructor()) {
                // construction: every argument may influence the new object state
                for (String arg : args) {
                    addEdgeRaw(graph, FlowGraph.key(fn.functionName(), arg),
                            FlowGraph.key(target.functionName(), thisParam),
                            line, FlowGraph.KIND_RECEIVER, target, thisParam);
                }
            } else {
                for (String receiver : jc.receiverVars()) {
                    addEdgeRaw(graph, FlowGraph.key(fn.functionName(), receiver),
                            FlowGraph.key(target.functionName(), thisParam),
                            line, FlowGraph.KIND_RECEIVER, target, thisParam);
                }
                if (jc.receiverVars().isEmpty()) {
                    // unqualified this-call: caller's $this is the receiver
                    addEdgeRaw(graph, FlowGraph.key(fn.functionName(), "$this"),
                            FlowGraph.key(target.functionName(), thisParam),
                            line, FlowGraph.KIND_RECEIVER, target, thisParam);
                }
            }
        }
        if (call.dst() != null) {
            registerLocal(graph, fn, call.dst());
            addEdgeRaw(graph, FlowGraph.key(target.functionName(), FlowGraph.RET_VAR),
                    FlowGraph.key(fn.functionName(), call.dst()),
                    line, FlowGraph.KIND_CALL_RETURN, target, call.dst());
            if (target.instance() && !jc.isConstructor()) {
                // Conservative: an instance method result may expose receiver
                // state (accessors, builders returning this, values assembled
                // from fields), so let receiver taint reach the destination.
                for (String receiver : jc.receiverVars()) {
                    addEdgeRaw(graph, FlowGraph.key(fn.functionName(), receiver),
                            FlowGraph.key(fn.functionName(), call.dst()),
                            line, FlowGraph.KIND_CALL_RETURN, target, call.dst());
                }
            }
        }
    }

    /** All textual tokens by which a rule pattern may match this call. */
    private static List<String> calleeTokens(FunctionSummary fn, FunctionSummary.CallFact call,
                                             ClassIndex index) {
        Set<String> tokens = new LinkedHashSet<>();
        String callee = call.callee();
        tokens.add(callee);
        FunctionSummary.JavaCall jc = call.javaCall();
        for (String owner : jc.ownerTokens()) {
            if (owner == null || owner.isEmpty() || "$this*".equals(owner)) {
                if ("$this*".equals(owner)) {
                    addOwnerTokens(tokens, fn.ownerClass(), callee);
                    for (String sup : fn.supers()) {
                        addOwnerTokens(tokens, index.resolveType(sup, fn), callee);
                    }
                }
                continue;
            }
            String fqn = index.resolveType(owner, fn);
            addOwnerTokens(tokens, fqn, callee);
        }
        return new ArrayList<>(tokens);
    }

    private static void addOwnerTokens(Set<String> tokens, String ownerFqn, String callee) {
        if (ownerFqn == null || ownerFqn.isEmpty()) {
            return;
        }
        tokens.add(ownerFqn + "#" + callee);
        tokens.add(ownerFqn + "." + callee);
        tokens.add(ownerFqn);
        // simple class name form
        int dot = ownerFqn.lastIndexOf('.');
        if (dot >= 0) {
            tokens.add(ownerFqn.substring(dot + 1) + "#" + callee);
        }
    }

    // ------------------------------------------------------------- registration

    static String fieldNode(String ownerFqn, String field) {
        return "field:" + ownerFqn + "#" + field;
    }

    private static void registerMember(FlowGraph graph, FunctionSummary fn) {
        String cls = fn.ownerClass();
        String method = displayMethod(fn);
        graph.registerDescriptor(fn.functionName(), FlowGraph.RET_VAR,
                new FlowGraph.Descriptor(fn.file(), cls, method, FlowGraph.RET_VAR));
        int idx = 0;
        for (String param : fn.params()) {
            String display = fn.instance() && idx == 0 ? "this" : param;
            graph.registerDescriptor(fn.functionName(), param,
                    new FlowGraph.Descriptor(fn.file(), cls, method, display));
            idx++;
        }
        for (FunctionSummary.AssignFact a : fn.assignments()) {
            registerLocalDescriptor(graph, fn, a.dst(), method);
            for (String src : a.srcs()) {
                registerLocalDescriptor(graph, fn, src, method);
            }
        }
        for (FunctionSummary.CallFact call : fn.calls()) {
            if (call.dst() != null) {
                registerLocalDescriptor(graph, fn, call.dst(), method);
            }
            for (String arg : call.argVars()) {
                registerLocalDescriptor(graph, fn, arg, method);
            }
        }
        for (FunctionSummary.FieldReadFact r : fn.fieldReads()) {
            registerLocalDescriptor(graph, fn, r.temp(), method);
        }
    }

    private static String displayMethod(FunctionSummary fn) {
        String member = fn.memberName();
        if ("<init>".equals(member)) {
            String cls = fn.ownerClass();
            int dot = cls.lastIndexOf('.');
            return (dot < 0 ? cls : cls.substring(dot + 1)) + "<init>";
        }
        if ("<clinit>".equals(member)) {
            return "<clinit>";
        }
        if (member.startsWith("field:")) {
            return member;
        }
        return member;
    }

    private static void registerLocalDescriptor(FlowGraph graph, FunctionSummary fn, String var, String method) {
        if (var == null || var.startsWith("field:")) {
            return;
        }
        String key = FlowGraph.key(fn.functionName(), var);
        graph.registerDescriptor(fn.functionName(), var,
                new FlowGraph.Descriptor(fn.file(), fn.ownerClass(), method, var));
    }

    private static void registerLocal(FlowGraph graph, FunctionSummary fn, String var) {
        if (var == null) {
            return;
        }
        graph.registerDescriptor(fn.functionName(), var,
                new FlowGraph.Descriptor(fn.file(), fn.ownerClass(), displayMethod(fn), var));
    }

    private static void registerField(FlowGraph graph, String ownerFqn, String field, String file) {
        String node = fieldNode(ownerFqn, field);
        String cls = ownerFqn;
        int dot = cls.lastIndexOf('.');
        String simple = dot < 0 ? cls : cls.substring(dot + 1);
        graph.registerDescriptor2(node, new FlowGraph.Descriptor(file, ownerFqn,
                simple + "#" + field, simple + "." + field));
    }

    private static void addEdge(FlowGraph graph, FunctionSummary fn, String fromVar, String toVar,
                                int line, String kind) {
        registerLocal(graph, fn, fromVar);
        registerLocal(graph, fn, toVar);
        graph.addEdge(fn.functionName(), fromVar, fn.functionName(), toVar, line, kind);
    }

    private static void addEdgeRaw(FlowGraph graph, String fromKey, String toKey,
                                   int line, String kind, FunctionSummary targetOwner, String displayVar) {
        graph.addEdgeKey(fromKey, toKey, line, kind);
    }
}
