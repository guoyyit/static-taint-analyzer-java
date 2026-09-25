package com.github.guoyyit.statictaintanalyzerjava.domain;

/** Risk level of a finding; ordered HIGH > MEDIUM > LOW for sorting. */
public enum RiskLevel {
    HIGH(3), MEDIUM(2), LOW(1);

    private final int weight;

    RiskLevel(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }

    public static RiskLevel fromString(String s) {
        if (s == null) {
            return MEDIUM;
        }
        return switch (s.trim().toUpperCase()) {
            case "HIGH" -> HIGH;
            case "LOW" -> LOW;
            default -> MEDIUM;
        };
    }
}
