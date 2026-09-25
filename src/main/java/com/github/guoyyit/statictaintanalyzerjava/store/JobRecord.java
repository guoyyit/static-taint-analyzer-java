package com.github.guoyyit.statictaintanalyzerjava.store;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Durable journal entry for one analysis job. The journal is the recovery
 * source of truth: after a crash, jobs not in COMMITTED/FAILED state are
 * resumed from the last committed snapshot.
 */
public record JobRecord(String jobId,
                        State state,
                        String sourceDir,
                        String ruleHash,
                        long snapshotVersion,
                        Instant createdAt,
                        Instant updatedAt,
                        String error) {

    public enum State {PENDING, RUNNING, COMMITTED, FAILED}

    @JsonCreator
    public JobRecord(@JsonProperty("jobId") String jobId,
                     @JsonProperty("state") State state,
                     @JsonProperty("sourceDir") String sourceDir,
                     @JsonProperty("ruleHash") String ruleHash,
                     @JsonProperty("snapshotVersion") long snapshotVersion,
                     @JsonProperty("createdAt") Instant createdAt,
                     @JsonProperty("updatedAt") Instant updatedAt,
                     @JsonProperty("error") String error) {
        this.jobId = jobId;
        this.state = state == null ? State.PENDING : state;
        this.sourceDir = sourceDir == null ? "" : sourceDir;
        this.ruleHash = ruleHash == null ? "" : ruleHash;
        this.snapshotVersion = snapshotVersion;
        this.createdAt = createdAt == null ? Instant.EPOCH : createdAt;
        this.updatedAt = updatedAt == null ? Instant.EPOCH : updatedAt;
        this.error = error == null ? "" : error;
    }

    public static JobRecord pending(String jobId, String sourceDir, String ruleHash, Instant now) {
        return new JobRecord(jobId, State.PENDING, sourceDir, ruleHash, 0L, now, now, "");
    }

    public JobRecord withState(State state, long snapshotVersion, String error, Instant now) {
        return new JobRecord(jobId, state, sourceDir, ruleHash, snapshotVersion, createdAt, now,
                error == null ? "" : error);
    }

    public boolean needsRecovery() {
        return state == State.PENDING || state == State.RUNNING;
    }
}
