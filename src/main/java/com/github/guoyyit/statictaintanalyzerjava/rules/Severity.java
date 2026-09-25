package com.github.guoyyit.statictaintanalyzerjava.rules;

/**
 * Risk level of a rule or finding. Declaration order is from lowest to highest.
 */
public enum Severity {
    INFO, LOW, MEDIUM, HIGH, CRITICAL;

    public static Severity fromString(String s) {
        if (s == null) {
            return MEDIUM;
        }
        return switch (s.trim().toUpperCase()) {
            case "INFO" -> INFO;
            case "LOW" -> LOW;
            case "MEDIUM" -> MEDIUM;
            case "HIGH" -> HIGH;
            case "CRITICAL" -> CRITICAL;
            default -> throw new IllegalArgumentException("unknown severity: " + s);
        };
    }
}
