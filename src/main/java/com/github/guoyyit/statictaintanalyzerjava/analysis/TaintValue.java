package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.domain.TaintStep;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Taint attached to a variable/field/return value: the set of originating
 * source rules plus the ordered propagation path. Path length is capped so
 * loops and recursion always yield bounded, deterministic results.
 */
public final class TaintValue {

    /** Hard cap on recorded path length; guarantees bounded results. */
    public static final int MAX_PATH_LENGTH = 25;

    private final Set<String> sourceRuleIds;
    private final List<TaintStep> steps;

    private TaintValue(Set<String> sourceRuleIds, List<TaintStep> steps) {
        this.sourceRuleIds = Set.copyOf(new TreeSet<>(sourceRuleIds));
        this.steps = List.copyOf(steps);
    }

    public static TaintValue clean() {
        return new TaintValue(Set.of(), List.of());
    }

    public static TaintValue fromSource(String sourceRuleId, TaintStep origin) {
        return new TaintValue(Set.of(sourceRuleId), List.of(origin));
    }

    public boolean isTainted() {
        return !sourceRuleIds.isEmpty();
    }

    public Set<String> sourceRuleIds() {
        return sourceRuleIds;
    }

    public List<TaintStep> steps() {
        return steps;
    }

    /** Union of two taints; deterministic (sorted ids, left-then-right steps). */
    public TaintValue merge(TaintValue other) {
        if (other == null || !other.isTainted()) {
            return this;
        }
        if (!isTainted()) {
            return other;
        }
        Set<String> ids = new TreeSet<>(sourceRuleIds);
        ids.addAll(other.sourceRuleIds);
        List<TaintStep> merged = new ArrayList<>(steps);
        for (TaintStep s : other.steps) {
            if (merged.size() >= MAX_PATH_LENGTH) {
                break;
            }
            if (!merged.contains(s)) {
                merged.add(s);
            }
        }
        return new TaintValue(ids, merged);
    }

    /** Appends one propagation hop; no-op beyond the path cap (boundedness). */
    public TaintValue withStep(TaintStep step) {
        if (!isTainted() || steps.size() >= MAX_PATH_LENGTH || steps.contains(step)) {
            return this;
        }
        List<TaintStep> next = new ArrayList<>(steps);
        next.add(step);
        return new TaintValue(sourceRuleIds, next);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TaintValue other)) {
            return false;
        }
        return sourceRuleIds.equals(other.sourceRuleIds) && steps.equals(other.steps);
    }

    @Override
    public int hashCode() {
        return 31 * sourceRuleIds.hashCode() + steps.hashCode();
    }

    @Override
    public String toString() {
        return "TaintValue" + sourceRuleIds;
    }
}
