package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * One taint propagation path from a source to a sink. The {@link #fingerprint}
 * is a stable digest of (sink rule, source rule, ordered path steps): identical
 * inputs and rules always reproduce the identical fingerprint, which is used for
 * de-duplication, exemptions and incremental diffing.
 */
public record Finding(String fingerprint,
                      String sinkRuleId,
                      String sourceRuleId,
                      RiskLevel risk,
                      List<TaintStep> path,
                      SourceLocation sinkLocation,
                      String sinkMethodSignature,
                      String ruleHash,
                      long firstSeenVersion,
                      long lastSeenVersion) implements Comparable<Finding> {

    @JsonCreator
    public Finding(@JsonProperty("fingerprint") String fingerprint,
                   @JsonProperty("sinkRuleId") String sinkRuleId,
                   @JsonProperty("sourceRuleId") String sourceRuleId,
                   @JsonProperty("risk") RiskLevel risk,
                   @JsonProperty("path") List<TaintStep> path,
                   @JsonProperty("sinkLocation") SourceLocation sinkLocation,
                   @JsonProperty("sinkMethodSignature") String sinkMethodSignature,
                   @JsonProperty("ruleHash") String ruleHash,
                   @JsonProperty("firstSeenVersion") long firstSeenVersion,
                   @JsonProperty("lastSeenVersion") long lastSeenVersion) {
        this.fingerprint = fingerprint;
        this.sinkRuleId = sinkRuleId;
        this.sourceRuleId = sourceRuleId;
        this.risk = risk == null ? RiskLevel.MEDIUM : risk;
        this.path = path == null ? List.of() : List.copyOf(path);
        this.sinkLocation = sinkLocation;
        this.sinkMethodSignature = sinkMethodSignature == null ? "" : sinkMethodSignature;
        this.ruleHash = ruleHash == null ? "" : ruleHash;
        this.firstSeenVersion = firstSeenVersion;
        this.lastSeenVersion = lastSeenVersion;
    }

    /** Creates a finding whose fingerprint is derived from its content. */
    public static Finding create(String sinkRuleId, String sourceRuleId, RiskLevel risk,
                                 List<TaintStep> path, SourceLocation sinkLocation,
                                 String sinkMethodSignature, String ruleHash, long version) {
        String fp = fingerprintOf(sinkRuleId, sourceRuleId, path, sinkLocation);
        return new Finding(fp, sinkRuleId, sourceRuleId, risk, path, sinkLocation,
                sinkMethodSignature, ruleHash, version, version);
    }

    public static String fingerprintOf(String sinkRuleId, String sourceRuleId,
                                       List<TaintStep> path, SourceLocation sinkLocation) {
        StringBuilder sb = new StringBuilder();
        sb.append("sink=").append(sinkRuleId).append(";src=").append(sourceRuleId);
        sb.append(";at=").append(sinkLocation);
        for (TaintStep step : path) {
            sb.append(";step=").append(step.location()).append('|').append(step.description());
        }
        return sha256(sb.toString());
    }

    public static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder();
            for (byte b : digest) {
                out.append(Character.forDigit((b >> 4) & 0xF, 16));
                out.append(Character.forDigit(b & 0xF, 16));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public Finding withSeenVersions(long firstSeen, long lastSeen) {
        return new Finding(fingerprint, sinkRuleId, sourceRuleId, risk, path, sinkLocation,
                sinkMethodSignature, ruleHash, firstSeen, lastSeen);
    }

    /** Deterministic ordering: risk desc, then fingerprint asc. */
    @Override
    public int compareTo(Finding o) {
        int c = Integer.compare(o.risk.weight(), risk.weight());
        if (c != 0) return c;
        return fingerprint.compareTo(o.fingerprint);
    }

    /** De-duplicates by fingerprint and sorts deterministically. */
    public static List<Finding> dedupAndSort(Iterable<Finding> findings) {
        java.util.Map<String, Finding> byFp = new java.util.TreeMap<>();
        for (Finding f : findings) {
            byFp.merge(f.fingerprint(), f, (a, b) -> a.path().size() <= b.path().size() ? a : b);
        }
        List<Finding> out = new ArrayList<>(byFp.values());
        out.sort(Finding::compareTo);
        return out;
    }
}
