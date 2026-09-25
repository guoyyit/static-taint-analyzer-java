package com.github.guoyyit.statictaintanalyzerjava.analysis.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;
import java.util.TreeSet;

/**
 * Inter-procedural taint summary of one method. Computed by bounded fixpoint;
 * serialized into the snapshot so incremental runs can reuse unaffected methods.
 *
 * @param taintedParamIndexes params whose taint flows to the return value
 * @param returnTaintedBySourceRuleId non-empty when the return is tainted by an internal source
 * @param taintedFields fields (simple names) this method may taint
 */
public record MethodSummary(String signature,
                            Set<Integer> taintedParamIndexes,
                            String returnTaintedBySourceRuleId,
                            Set<String> taintedFields) {

    @JsonCreator
    public MethodSummary(@JsonProperty("signature") String signature,
                         @JsonProperty("taintedParamIndexes") Set<Integer> taintedParamIndexes,
                         @JsonProperty("returnTaintedBySourceRuleId") String returnTaintedBySourceRuleId,
                         @JsonProperty("taintedFields") Set<String> taintedFields) {
        this.signature = signature;
        this.taintedParamIndexes = taintedParamIndexes == null ? Set.of() : new TreeSet<>(taintedParamIndexes);
        this.returnTaintedBySourceRuleId = returnTaintedBySourceRuleId == null ? "" : returnTaintedBySourceRuleId;
        this.taintedFields = taintedFields == null ? Set.of() : new TreeSet<>(taintedFields);
    }

    public static MethodSummary empty(String signature) {
        return new MethodSummary(signature, Set.of(), "", Set.of());
    }

    public boolean returnTaintedForAny(Set<Integer> taintedArgs) {
        if (!returnTaintedBySourceRuleId.isEmpty()) {
            return true;
        }
        for (int i : taintedParamIndexes) {
            if (taintedArgs.contains(i)) {
                return true;
            }
        }
        return false;
    }
}
