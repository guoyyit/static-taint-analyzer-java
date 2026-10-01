package com.github.guoyyit.statictaintanalyzerjava.lang.java;

/**
 * Thrown when a Java source file cannot be parsed. Carries the file name,
 * 1-based line number and a machine-readable failure reason so individual
 * file failures can be reported without aborting the whole project analysis.
 */
public final class JavaParseException extends RuntimeException {

    /** Distinct failure reasons surfaced in per-file parse failure reports. */
    public enum Reason {
        /** The source contains characters or tokens that are not lexically valid Java. */
        LEXICAL,
        /** Tokens were produced, but they do not form valid Java syntax. */
        SYNTAX,
        /** A valid Java construct was encountered that the analyzer does not model. */
        UNSUPPORTED
    }

    private final String file;
    private final int line;
    private final Reason reason;

    public JavaParseException(String file, int line, Reason reason, String message) {
        super(message);
        this.file = file;
        this.line = line;
        this.reason = reason;
    }

    public String file() {
        return file;
    }

    public int line() {
        return line;
    }

    public Reason reason() {
        return reason;
    }
}
