package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.List;
import java.util.Map;

/**
 * Intra-procedural flow facts of one function. Depends only on the function's own
 * source text and the rule set, therefore cacheable per file content hash.
 */
public record FunctionSummary(String functionName,
                              String file,
                              List<String> params,
                              List<AssignFact> assignments,
                              List<CallFact> calls,
                              List<ReturnFact> returns,
                              List<SourceFact> sources,
                              List<SinkFact> sinks,
                              String className,
                              boolean isStatic,
                              boolean isConstructor,
                              List<String> imports,
                              List<AliasFact> aliases,
                              Map<String, String> varTypes,
                              int declLine) {

    public FunctionSummary {
        params = List.copyOf(params);
        assignments = List.copyOf(assignments);
        calls = List.copyOf(calls);
        returns = List.copyOf(returns);
        sources = List.copyOf(sources);
        sinks = List.copyOf(sinks);
        className = className == null ? "" : className;
        imports = imports == null ? List.of() : List.copyOf(imports);
        aliases = aliases == null ? List.of() : List.copyOf(aliases);
        varTypes = varTypes == null ? Map.of() : Map.copyOf(varTypes);
    }

    /** Constructor used by the legacy DSL frontend (no class/Java metadata). */
    public FunctionSummary(String functionName, String file, List<String> params,
                           List<AssignFact> assignments, List<CallFact> calls,
                           List<ReturnFact> returns, List<SourceFact> sources, List<SinkFact> sinks) {
        this(functionName, file, params, assignments, calls, returns, sources, sinks,
                "", false, false, List.of(), List.of(), Map.of(), 0);
    }

    /** dst receives the union of srcs (sanitizer calls produce no fact). */
    public record AssignFact(String dst, List<String> srcs, int line) {
    }

    /**
     * Call site. For the legacy DSL only the first five fields are used.
     * Java calls additionally carry:
     * receiverVar     - access path of the receiver object (nullable; $this for this/super calls)
     * qualifierType   - simple/qualified type name before a static {@code T.m(...)} call (nullable)
     * newType         - instantiated type name for {@code new T(...)} (nullable)
     */
    public record CallFact(String callSiteId, String callee, List<String> argVars, String dst, int line,
                           String receiverVar, String qualifierType, String newType, int argCount) {
        public CallFact {
            argVars = List.copyOf(argVars);
        }

        /** Constructor used by the legacy DSL frontend. */
        public CallFact(String callSiteId, String callee, List<String> argVars, String dst, int line) {
            this(callSiteId, callee, argVars, dst, line, null, null, null, argVars.size());
        }
    }

    /**
     * Two names alias the same object reference: field taint observed through
     * either name is shared (bidirectional, per observed field suffix).
     */
    public record AliasFact(String left, String right, int line) {
    }

    public record ReturnFact(List<String> srcs, int line) {
    }

    public record SourceFact(String ruleId, String dst, int line) {
    }

    public record SinkFact(String ruleId, List<String> argVars, int line) {
    }
}
