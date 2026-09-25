package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Immutable, versioned set of declarative taint rules. The {@link #hash} is a
 * canonical digest of the rule content: any rule change yields a new hash, which
 * invalidates exemptions and forces a full re-analysis so old and new results
 * are never mixed.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleSet(String version,
                      List<TaintRule> sources,
                      List<TaintRule> sinks,
                      List<TaintRule> sanitizers,
                      String hash) {

    @JsonCreator
    public RuleSet(@JsonProperty("version") String version,
                   @JsonProperty("sources") List<TaintRule> sources,
                   @JsonProperty("sinks") List<TaintRule> sinks,
                   @JsonProperty("sanitizers") List<TaintRule> sanitizers) {
        this(version, sources, sinks, sanitizers,
                computeHash(version, sources, sinks, sanitizers));
    }

    public RuleSet(String version, List<TaintRule> sources, List<TaintRule> sinks,
                   List<TaintRule> sanitizers, String hash) {
        this.version = version == null ? "0" : version;
        this.sources = sorted(sources);
        this.sinks = sorted(sinks);
        this.sanitizers = sorted(sanitizers);
        this.hash = hash;
    }

    private static List<TaintRule> sorted(List<TaintRule> rules) {
        List<TaintRule> copy = new ArrayList<>(rules == null ? List.of() : rules);
        copy.sort(Comparator.comparing(TaintRule::id).thenComparing(TaintRule::pattern));
        return List.copyOf(copy);
    }

    public static RuleSet empty() {
        return new RuleSet("0", List.of(), List.of(), List.of());
    }

    @JsonIgnore
    public Optional<TaintRule> matchSource(String receiverType, String methodName) {
        return sources.stream().filter(r -> r.matches(receiverType, methodName)).findFirst();
    }

    @JsonIgnore
    public Optional<TaintRule> matchSink(String receiverType, String methodName) {
        return sinks.stream().filter(r -> r.matches(receiverType, methodName)).findFirst();
    }

    @JsonIgnore
    public Optional<TaintRule> matchSanitizer(String receiverType, String methodName) {
        return sanitizers.stream().filter(r -> r.matches(receiverType, methodName)).findFirst();
    }

    private static String computeHash(String version, List<TaintRule> sources,
                                      List<TaintRule> sinks, List<TaintRule> sanitizers) {
        String canonical = canonical(version, sources, sinks, sanitizers);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(canonical.getBytes(StandardCharsets.UTF_8));
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

    private static String canonical(String version, List<TaintRule> sources,
                                    List<TaintRule> sinks, List<TaintRule> sanitizers) {
        StringBuilder sb = new StringBuilder("v=").append(version == null ? "0" : version);
        appendRules(sb, "src", sources);
        appendRules(sb, "snk", sinks);
        appendRules(sb, "san", sanitizers);
        return sb.toString();
    }

    private static void appendRules(StringBuilder sb, String kind, List<TaintRule> rules) {
        for (TaintRule r : sorted(rules)) {
            sb.append('|').append(kind).append(':').append(r.id()).append(':')
                    .append(r.pattern()).append(':').append(r.risk()).append(':').append(r.message());
        }
    }
}
