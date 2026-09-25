package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/** Append-only audit record for exemptions, rule changes and analysis commits. */
public record AuditEvent(Instant timestamp, String type, String actor, String details) {

    @JsonCreator
    public AuditEvent(@JsonProperty("timestamp") Instant timestamp,
                      @JsonProperty("type") String type,
                      @JsonProperty("actor") String actor,
                      @JsonProperty("details") String details) {
        this.timestamp = timestamp == null ? Instant.EPOCH : timestamp;
        this.type = type == null ? "" : type;
        this.actor = actor == null ? "" : actor;
        this.details = details == null ? "" : details;
    }
}
