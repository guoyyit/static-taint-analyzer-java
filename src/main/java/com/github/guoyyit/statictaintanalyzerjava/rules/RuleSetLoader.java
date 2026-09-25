package com.github.guoyyit.statictaintanalyzerjava.rules;

import com.github.guoyyit.statictaintanalyzerjava.domain.RuleSet;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Loads and validates declarative rule sets (JSON). */
public final class RuleSetLoader {

    private final com.fasterxml.jackson.databind.ObjectMapper mapper =
            new com.fasterxml.jackson.databind.ObjectMapper();

    public RuleSet load(Path file) {
        try {
            return parse(Files.readString(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public RuleSet parse(String json) {
        try {
            RuleSet rules = mapper.readValue(json, RuleSet.class);
            validate(rules);
            return rules;
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid rule set: " + e.getMessage(), e);
        }
    }

    public Optional<RuleSet> loadIfExists(Path file) {
        return Files.exists(file) ? Optional.of(load(file)) : Optional.empty();
    }

    private void validate(RuleSet rules) {
        for (TaintRuleId id : ids(rules)) {
            if (id.count > 1) {
                throw new IllegalArgumentException("duplicate rule id: " + id.id);
            }
        }
    }

    private java.util.List<TaintRuleId> ids(RuleSet rules) {
        java.util.Map<String, Integer> counts = new java.util.TreeMap<>();
        rules.sources().forEach(r -> counts.merge(r.id(), 1, Integer::sum));
        rules.sinks().forEach(r -> counts.merge(r.id(), 1, Integer::sum));
        rules.sanitizers().forEach(r -> counts.merge(r.id(), 1, Integer::sum));
        return counts.entrySet().stream().map(e -> new TaintRuleId(e.getKey(), e.getValue())).toList();
    }

    private record TaintRuleId(String id, int count) {
    }
}
