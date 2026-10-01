package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.List;

/**
 * Intra-procedural flow facts of one function. Depends only on the function's own
 * source text and the rule set, therefore cacheable per file content hash.
 *
 * <p>The first 8 fields describe the original analyzed DSL; Java members carry
 * fully qualified owner/member names, parameter types and explicit field access
 * facts, while {@code calls} entries carry a nullable {@link JavaCall} detail.
 */
public record FunctionSummary(String functionName,
                              String file,
                              List<String> params,
                              List<AssignFact> assignments,
                              List<CallFact> calls,
                              List<ReturnFact> returns,
                              List<SourceFact> sources,
                              List<SinkFact> sinks,
                              String ownerClass,
                              String memberName,
                              String packageName,
                              List<String> paramTypes,
                              List<String> imports,
                              List<String> supers,
                              boolean instance,
                              List<FieldWriteFact> fieldWrites,
                              List<FieldReadFact> fieldReads) {

    /** DSL constructor: no Java type information. */
    public FunctionSummary(String functionName, String file, List<String> params,
                           List<AssignFact> assignments, List<CallFact> calls,
                           List<ReturnFact> returns, List<SourceFact> sources,
                           List<SinkFact> sinks) {
        this(functionName, file, params, assignments, calls, returns, sources, sinks,
                "", functionName, "", List.of(), List.of(), List.of(), false, List.of(), List.of());
    }

    /**
     * Marker summary for a declared Java type that has no lowered member. It
     * carries only structural type metadata (package/imports/supertypes) so the
     * {@code ClassIndex} can traverse inheritance through empty classes, marker
     * interfaces and enums. It contributes no flow edges.
     */
    public static FunctionSummary javaTypeMarker(String ownerFqn, String file, String packageName,
                                                 List<String> imports, List<String> supers) {
        return new FunctionSummary(ownerFqn + "#<type>", file, List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), ownerFqn, "<type>", packageName,
                List.of(), List.copyOf(imports), List.copyOf(supers), false, List.of(), List.of());
    }

    /** dst receives the union of srcs (sanitizer calls produce no fact). */
    public record AssignFact(String dst, List<String> srcs, int line) {
    }

    /** Call site: callee invoked with argVars, result assigned to dst (nullable). */
    public record CallFact(String callSiteId, String callee, List<String> argVars, String dst,
                           int line, JavaCall javaCall) {

        /** DSL call site. */
        public CallFact(String callSiteId, String callee, List<String> argVars, String dst, int line) {
            this(callSiteId, callee, argVars, dst, line, null);
        }
    }

    /**
     * Java call details. {@code ownerTokens} are intra-procedurally resolved type
     * tokens for the receiver (simple + qualified forms); {@code "*this*"} marks
     * an implicit/this receiver.
     */
    public record JavaCall(List<String> ownerTokens, boolean isStatic, boolean isConstructor,
                           List<String> receiverVars, List<String> resultTypeHints) {

        public JavaCall(List<String> ownerTokens, boolean isStatic, boolean isConstructor) {
            this(ownerTokens, isStatic, isConstructor, List.of(), List.of());
        }

        public JavaCall(List<String> ownerTokens, boolean isStatic, boolean isConstructor,
                        List<String> receiverVars) {
            this(ownerTokens, isStatic, isConstructor, receiverVars, List.of());
        }
    }

    /** A field write {@code owner.field <- srcs}; resolved to concrete fields globally. */
    public record FieldWriteFact(String field, List<String> ownerTokens, List<String> srcs, int line) {
    }

    /** A field read lowered into a fresh local temp {@code temp <- owner.field}. */
    public record FieldReadFact(String temp, String field, List<String> ownerTokens, int line) {
    }

    public record ReturnFact(List<String> srcs, int line) {
    }

    public record SourceFact(String ruleId, String dst, int line) {
    }

    public record SinkFact(String ruleId, List<String> argVars, int line) {
    }
}
