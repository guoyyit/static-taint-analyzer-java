package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/** One hop of a taint propagation path. */
public record TaintStep(SourceLocation location, String description) implements Comparable<TaintStep> {

    @JsonCreator
    public TaintStep(@JsonProperty("location") SourceLocation location,
                     @JsonProperty("description") String description) {
        this.location = location;
        this.description = description == null ? "" : description;
    }

    @Override
    public int compareTo(TaintStep o) {
        int c = location.compareTo(o.location);
        if (c != 0) return c;
        return description.compareTo(o.description);
    }

    @Override
    public String toString() {
        return description + " @ " + location;
    }
}
