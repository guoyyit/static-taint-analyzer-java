package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.List;

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
                              List<SinkFact> sinks) {

    /** dst receives the union of srcs (sanitizer calls produce no fact). */
    public record AssignFact(String dst, List<String> srcs, int line) {
    }

    /** Call site: callee invoked with argVars, result assigned to dst (nullable). */
    public record CallFact(String callSiteId, String callee, List<String> argVars, String dst, int line) {
    }

    public record ReturnFact(List<String> srcs, int line) {
    }

    public record SourceFact(String ruleId, String dst, int line) {
    }

    public record SinkFact(String ruleId, List<String> argVars, int line) {
    }
}
