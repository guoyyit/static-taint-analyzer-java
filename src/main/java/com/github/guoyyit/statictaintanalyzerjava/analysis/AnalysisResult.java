package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.List;
import java.util.Map;

/**
 * Immutable outcome of analyzing one commit. Summaries are kept so the next
 * commit can reuse unchanged files (keyed by content hash + rules hash).
 */
public record AnalysisResult(String rulesHash,
                             Map<String, String> fileHashes,
                             Map<String, FunctionSummary> summaries,
                             List<Finding> findings,
                             List<String> removedFingerprints,
                             AnalysisStats stats) {

    /** Incremental cache observability. */
    public record AnalysisStats(int reusedFiles, int reparsedFiles) {
    }
}
