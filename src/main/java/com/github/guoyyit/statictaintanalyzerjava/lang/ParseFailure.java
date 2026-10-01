package com.github.guoyyit.statictaintanalyzerjava.lang;

/**
 * One file-level parse failure, isolated from the rest of the project.
 * Always carries the file name, a 1-based line (0 when unknown) and a stable
 * machine-readable {@code code} distinguishing failure reasons.
 */
public record ParseFailure(String file, int line, String code, String message) {

    /** Lexer could not tokenize the source (illegal character, unterminated literal, ...). */
    public static final String CODE_LEXICAL = "LEXICAL_ERROR";
    /** Tokens did not form valid Java syntax. */
    public static final String CODE_SYNTAX = "SYNTAX_ERROR";
    /** Source could not be read from disk. */
    public static final String CODE_IO = "IO_ERROR";
    /** Internal/unsupported-construct failure while lowering the parse tree. */
    public static final String CODE_INTERNAL = "INTERNAL_ERROR";

    public static ParseFailure lexical(String file, int line, String message) {
        return new ParseFailure(file, line, CODE_LEXICAL, message);
    }

    public static ParseFailure syntax(String file, int line, String message) {
        return new ParseFailure(file, line, CODE_SYNTAX, message);
    }

    public static ParseFailure io(String file, String message) {
        return new ParseFailure(file, 0, CODE_IO, message);
    }

    public static ParseFailure internal(String file, int line, String message) {
        return new ParseFailure(file, line, CODE_INTERNAL, message);
    }
}
