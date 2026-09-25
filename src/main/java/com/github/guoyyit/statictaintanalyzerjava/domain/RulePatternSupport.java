package com.github.guoyyit.statictaintanalyzerjava.domain;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/** Glob-style matcher used by {@link TaintRule}; results are cached and deterministic. */
final class RulePatternSupport {

    private static final Map<String, Pattern> CACHE = new ConcurrentHashMap<>();

    private RulePatternSupport() {
    }

    static boolean matches(String pattern, String className, String methodName) {
        if (pattern == null || pattern.isEmpty()) {
            return false;
        }
        String cls = className == null ? "" : className;
        String full = cls.isEmpty() ? methodName : cls + "." + methodName;
        // A pattern without a dot matches the bare method name only.
        if (!pattern.contains(".")) {
            return glob(pattern).matcher(methodName).matches();
        }
        if (glob(pattern).matcher(full).matches()) {
            return true;
        }
        // Also try matching against the simple class name for convenience.
        String simple = cls.contains(".") ? cls.substring(cls.lastIndexOf('.') + 1) : cls;
        String simpleFull = simple.isEmpty() ? methodName : simple + "." + methodName;
        return glob(pattern).matcher(simpleFull).matches();
    }

    private static Pattern glob(String glob) {
        return CACHE.computeIfAbsent(glob, g -> {
            StringBuilder sb = new StringBuilder();
            for (char c : g.toCharArray()) {
                switch (c) {
                    case '*' -> sb.append(".*");
                    case '?' -> sb.append('.');
                    case '.', '(', ')', '[', ']', '{', '}', '+', '^', '$', '|', '\\' -> sb.append('\\').append(c);
                    default -> sb.append(c);
                }
            }
            return Pattern.compile(sb.toString());
        });
    }
}
