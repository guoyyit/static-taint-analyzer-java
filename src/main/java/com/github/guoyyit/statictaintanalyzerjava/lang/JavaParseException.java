package com.github.guoyyit.statictaintanalyzerjava.lang;

/**
 * Thrown when a single Java file cannot be parsed/lowered. Carries a fully
 * qualified {@link ParseFailure}; callers isolate it per file.
 */
public final class JavaParseException extends RuntimeException {

    private final transient ParseFailure failure;

    public JavaParseException(ParseFailure failure) {
        super(failure.file() + ":" + failure.line() + " " + failure.code() + ": " + failure.message());
        this.failure = failure;
    }

    public ParseFailure failure() {
        return failure;
    }
}
