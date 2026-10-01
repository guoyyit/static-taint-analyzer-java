package com.github.guoyyit.statictaintanalyzerjava.analysis;

/**
 * Report of one file that could not be parsed. Failures never abort analysis of
 * the remaining files; each failure records the file, 1-based line and a
 * machine-readable reason so callers can distinguish failure causes.
 */
public record ParseFailure(String file, int line, String reason, String message) {

    public static final String LEXICAL = "LEXICAL";
    public static final String SYNTAX = "SYNTAX";
    public static final String UNSUPPORTED = "UNSUPPORTED";
    public static final String IO = "IO";
}
