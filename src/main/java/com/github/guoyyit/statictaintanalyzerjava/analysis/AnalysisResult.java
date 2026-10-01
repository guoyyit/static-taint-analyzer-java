package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.ParseFailure;

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
                             AnalysisStats stats,
                             List<ParseFailure> parseFailures,
                             List<String> removedFiles) {

    /** Jackson compact constructor: normalize missing fields from older commits. */
    public AnalysisResult {
        fileHashes = fileHashes == null ? Map.of() : fileHashes;
        summaries = summaries == null ? Map.of() : summaries;
        findings = findings == null ? List.of() : findings;
        removedFingerprints = removedFingerprints == null ? List.of() : removedFingerprints;
        parseFailures = parseFailures == null ? List.of() : parseFailures;
        removedFiles = removedFiles == null ? List.of() : removedFiles;
        if (stats == null) {
            stats = new AnalysisStats(0, 0, 0, 0);
        }
    }

    /** DSL/previous-shape constructor without per-file failures. */
    public AnalysisResult(String rulesHash, Map<String, String> fileHashes,
                          Map<String, FunctionSummary> summaries, List<Finding> findings,
                          List<String> removedFingerprints, AnalysisStats stats) {
        this(rulesHash, fileHashes, summaries, findings, removedFingerprints, stats, List.of(), List.of());
    }

    /** Incremental cache observability. */
    public record AnalysisStats(int reusedFiles, int reparsedFiles, int failedFiles, int removedFiles) {

        public AnalysisStats(int reusedFiles, int reparsedFiles) {
            this(reusedFiles, reparsedFiles, 0, 0);
        }
    }
}
