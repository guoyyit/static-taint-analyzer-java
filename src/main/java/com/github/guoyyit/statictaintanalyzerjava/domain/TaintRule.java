package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Declarative rule for a taint source, sink or sanitizer.
 * Pattern format: {@code fully.qualified.ClassName.methodName} with optional
 * trailing/leading {@code *} wildcards, e.g. {@code javax.servlet.http.HttpServletRequest.get*},
 * {@code *.executeQuery} or plain {@code methodName} matching any class.
 */
public record TaintRule(String id, String pattern, RiskLevel risk, String message) {

    @JsonCreator
    public static TaintRule of(@JsonProperty("id") String id,
                               @JsonProperty("pattern") String pattern,
                               @JsonProperty("risk") String risk,
                               @JsonProperty("message") String message) {
        return new TaintRule(id, pattern, RiskLevel.fromString(risk), message);
    }

    public TaintRule {
        id = id == null ? "" : id;
        pattern = pattern == null ? "" : pattern;
        risk = risk == null ? RiskLevel.MEDIUM : risk;
        message = message == null ? "" : message;
    }

    /** Matches a call described by receiver type (may be empty) and method name. */
    public boolean matches(String receiverType, String methodName) {
        return RulePatternSupport.matches(pattern, receiverType, methodName);
    }

    /** Matches a method signature such as {@code com.foo.Controller#handle(String)}. */
    public boolean matchesSignature(String className, String methodName) {
        return RulePatternSupport.matches(pattern, className, methodName);
    }
}
