package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.Severity;

import java.util.List;

/**
 * One taint propagation path from a source to a sink.
 * The fingerprint is a stable content hash of the canonical path signature.
 */
public record Finding(String fingerprint,
                      String sourceRuleId,
                      String sinkRuleId,
                      Severity severity,
                      List<Step> path,
                      String status) {

    /** Lifecycle vs. the parent commit. */
    public static final String STATUS_NEW = "NEW";
    public static final String STATUS_UNCHANGED = "UNCHANGED";
    public static final String STATUS_REMOVED = "REMOVED";

    public record Step(String file, String function, String variable, int line, String kind) {
    }
}
