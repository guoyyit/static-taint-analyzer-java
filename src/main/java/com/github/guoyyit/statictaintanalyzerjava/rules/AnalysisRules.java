package com.github.guoyyit.statictaintanalyzerjava.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Declarative taint rules: sources, sinks and sanitizers, matched by callee-name
 * pattern (exact name or glob with '*'). The canonical hash identifies a rule set;
 * findings and exemptions are bound to it, so a rule change never mixes with old results.
 */
public record AnalysisRules(List<SourceRule> sources,
                            List<SinkRule> sinks,
                            List<SanitizerRule> sanitizers) {

    public record SourceRule(String id, String pattern, Severity severity) {
    }

    public record SinkRule(String id, String pattern, Severity severity) {
    }

    public record SanitizerRule(String id, String pattern) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Compact constructor: sort rules by id so every downstream iteration is deterministic. */
    public AnalysisRules {
        sources = List.copyOf(sorted(sources, SourceRule::id));
        sinks = List.copyOf(sorted(sinks, SinkRule::id));
        sanitizers = List.copyOf(sorted(sanitizers, SanitizerRule::id));
    }

    private static <T> List<T> sorted(List<T> rules, java.util.function.Function<T, String> id) {
        List<T> copy = new ArrayList<>(rules == null ? List.of() : rules);
        copy.sort(Comparator.comparing(id));
        return copy;
    }

    public static AnalysisRules fromJson(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            List<SourceRule> sources = new ArrayList<>();
            for (JsonNode n : root.path("sources")) {
                sources.add(new SourceRule(
                        required(n, "id"), required(n, "pattern"),
                        Severity.fromString(n.path("severity").asText("MEDIUM"))));
            }
            List<SinkRule> sinks = new ArrayList<>();
            for (JsonNode n : root.path("sinks")) {
                sinks.add(new SinkRule(
                        required(n, "id"), required(n, "pattern"),
                        Severity.fromString(n.path("severity").asText("HIGH"))));
            }
            List<SanitizerRule> sanitizers = new ArrayList<>();
            for (JsonNode n : root.path("sanitizers")) {
                sanitizers.add(new SanitizerRule(required(n, "id"), required(n, "pattern")));
            }
            return new AnalysisRules(sources, sinks, sanitizers);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid rules json: " + e.getMessage(), e);
        }
    }

    private static String required(JsonNode n, String field) {
        String v = n.path(field).asText(null);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("rule missing required field: " + field);
        }
        return v;
    }

    /** Canonical JSON: rules sorted by id, fields in fixed order, no whitespace. */
    public String canonicalJson() {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode src = root.putArray("sources");
        for (SourceRule r : sources) {
            src.addObject().put("id", r.id()).put("pattern", r.pattern()).put("severity", r.severity().name());
        }
        ArrayNode snk = root.putArray("sinks");
        for (SinkRule r : sinks) {
            snk.addObject().put("id", r.id()).put("pattern", r.pattern()).put("severity", r.severity().name());
        }
        ArrayNode san = root.putArray("sanitizers");
        for (SanitizerRule r : sanitizers) {
            san.addObject().put("id", r.id()).put("pattern", r.pattern());
        }
        return root.toString();
    }

    /** Stable SHA-256 over the canonical JSON form. */
    public String hash() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(canonicalJson().getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public SourceRule matchSource(String callee) {
        for (SourceRule r : sources) {
            if (matches(r.pattern(), callee)) {
                return r;
            }
        }
        return null;
    }

    public SinkRule matchSink(String callee) {
        for (SinkRule r : sinks) {
            if (matches(r.pattern(), callee)) {
                return r;
            }
        }
        return null;
    }

    public boolean isSanitizer(String callee) {
        for (SanitizerRule r : sanitizers) {
            if (matches(r.pattern(), callee)) {
                return true;
            }
        }
        return false;
    }

    /** Exact name or glob with '*' wildcards. */
    static boolean matches(String pattern, String name) {
        if (pattern.indexOf('*') < 0) {
            return pattern.equals(name);
        }
        StringBuilder regex = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            if (c == '*') {
                regex.append(".*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return name.matches(regex.toString());
    }
}
