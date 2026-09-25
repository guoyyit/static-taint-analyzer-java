package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Immutable result of one committed analysis. Readers only ever observe a fully
 * committed snapshot; a new snapshot replaces the old one atomically.
 *
 * @param fileHashes      path -> sha256 of file content at analysis time (incremental input)
 * @param methodSummaries method signature -> serialized taint summary (incremental state)
 * @param findingsByMethod sink method signature -> fingerprints produced there (incremental index)
 */
public record AnalysisSnapshot(long version,
                               Instant committedAt,
                               String ruleHash,
                               List<Finding> findings,
                               Map<String, String> fileHashes,
                               Map<String, String> methodSummaries,
                               Map<String, List<String>> findingsByMethod) {

    @JsonCreator
    public AnalysisSnapshot(@JsonProperty("version") long version,
                            @JsonProperty("committedAt") Instant committedAt,
                            @JsonProperty("ruleHash") String ruleHash,
                            @JsonProperty("findings") List<Finding> findings,
                            @JsonProperty("fileHashes") Map<String, String> fileHashes,
                            @JsonProperty("methodSummaries") Map<String, String> methodSummaries,
                            @JsonProperty("findingsByMethod") Map<String, List<String>> findingsByMethod) {
        this.version = version;
        this.committedAt = committedAt == null ? Instant.EPOCH : committedAt;
        this.ruleHash = ruleHash == null ? "" : ruleHash;
        this.findings = findings == null ? List.of() : List.copyOf(findings);
        this.fileHashes = fileHashes == null ? Map.of() : Map.copyOf(fileHashes);
        this.methodSummaries = methodSummaries == null ? Map.of() : Map.copyOf(methodSummaries);
        this.findingsByMethod = findingsByMethod == null ? Map.of() : deepCopy(findingsByMethod);
    }

    private static Map<String, List<String>> deepCopy(Map<String, List<String>> in) {
        Map<String, List<String>> out = new TreeMap<>();
        in.forEach((k, v) -> out.put(k, List.copyOf(v)));
        return Map.copyOf(out);
    }

    public static AnalysisSnapshot empty() {
        return new AnalysisSnapshot(0, Instant.EPOCH, "", List.of(), Map.of(), Map.of(), Map.of());
    }
}
