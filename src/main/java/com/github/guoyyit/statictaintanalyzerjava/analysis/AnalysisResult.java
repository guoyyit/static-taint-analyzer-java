package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.List;
import java.util.Map;

/**
 * Immutable outcome of analyzing one commit. Summaries and Java structural
 * metadata are kept so the next commit reuses unchanged files (keyed by content
 * hash + rules hash) even after a restart; everything stored here is plain data
 * that round-trips through the JSON commit store.
 */
public record AnalysisResult(String rulesHash,
                             Map<String, String> fileHashes,
                             Map<String, FunctionSummary> summaries,
                             List<Finding> findings,
                             List<String> removedFingerprints,
                             AnalysisStats stats,
                             List<String> removedFiles,
                             List<String> addedFiles,
                             List<ParseFailure> parseFailures,
                             List<TypeMeta> typeMetas,
                             Map<String, List<String>> importsByType,
                             Map<String, List<ClassModel.MethodSig>> methodsByType,
                             Map<String, List<TypeMeta>> typeMetasByFile) {

    /** Constructor used by the legacy DSL-only flow before directory/Java support. */
    public AnalysisResult(String rulesHash, Map<String, String> fileHashes,
                          Map<String, FunctionSummary> summaries, List<Finding> findings,
                          List<String> removedFingerprints, AnalysisStats stats) {
        this(rulesHash, fileHashes, summaries, findings, removedFingerprints, stats,
                List.of(), List.of(), List.of(), List.of(), Map.of(), Map.of(), Map.of());
    }

    public AnalysisResult {
        removedFiles = removedFiles == null ? List.of() : List.copyOf(removedFiles);
        addedFiles = addedFiles == null ? List.of() : List.copyOf(addedFiles);
        parseFailures = parseFailures == null ? List.of() : List.copyOf(parseFailures);
        typeMetas = typeMetas == null ? List.of() : List.copyOf(typeMetas);
        importsByType = importsByType == null ? Map.of() : Map.copyOf(importsByType);
        methodsByType = methodsByType == null ? Map.of() : Map.copyOf(methodsByType);
        typeMetasByFile = typeMetasByFile == null ? Map.of() : Map.copyOf(typeMetasByFile);
    }

    /** Incremental cache observability. */
    public record AnalysisStats(int reusedFiles, int reparsedFiles, int unchangedFiles,
                                int failedFiles, int totalFiles) {

        /** Legacy constructor: unchanged/total derived, failures not tracked. */
        public AnalysisStats(int reusedFiles, int reparsedFiles) {
            this(reusedFiles, reparsedFiles, reusedFiles, 0, reusedFiles + reparsedFiles);
        }
    }
}
