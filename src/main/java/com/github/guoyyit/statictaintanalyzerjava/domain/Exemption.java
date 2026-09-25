package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Suppresses one finding (by fingerprint). An exemption only applies while it is
 * unexpired AND the rule hash it was created under still matches the active rules;
 * expiring or changing the rules restores detection automatically.
 */
public record Exemption(String id,
                        String fingerprint,
                        String reason,
                        String createdBy,
                        Instant createdAt,
                        Instant expiresAt,
                        String ruleHash) {

    @JsonCreator
    public Exemption(@JsonProperty("id") String id,
                     @JsonProperty("fingerprint") String fingerprint,
                     @JsonProperty("reason") String reason,
                     @JsonProperty("createdBy") String createdBy,
                     @JsonProperty("createdAt") Instant createdAt,
                     @JsonProperty("expiresAt") Instant expiresAt,
                     @JsonProperty("ruleHash") String ruleHash) {
        this.id = id;
        this.fingerprint = fingerprint;
        this.reason = reason == null ? "" : reason;
        this.createdBy = createdBy == null ? "" : createdBy;
        this.createdAt = createdAt == null ? Instant.EPOCH : createdAt;
        this.expiresAt = expiresAt; // null = never expires
        this.ruleHash = ruleHash == null ? "" : ruleHash;
    }

    public boolean isExpired(Instant now) {
        return expiresAt != null && !now.isBefore(expiresAt);
    }

    public boolean appliesTo(Finding finding, Instant now) {
        if (!fingerprint.equals(finding.fingerprint())) {
            return false;
        }
        if (isExpired(now)) {
            return false;
        }
        // Rule changes invalidate the exemption so detection resumes.
        return ruleHash.equals(finding.ruleHash());
    }
}
