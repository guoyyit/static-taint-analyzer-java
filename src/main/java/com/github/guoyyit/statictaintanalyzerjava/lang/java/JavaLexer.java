package com.github.guoyyit.statictaintanalyzerjava.lang.java;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Deterministic hand-written lexer for the supported Java subset:
 * comments, string/char/text-block literals (content irrelevant to taint,
 * normalized to empty text), numeric literals, identifiers and operators.
 */
public final class JavaLexer {

    public enum TokenKind {
        IDENT, INT_LITERAL, FLOAT_LITERAL, CHAR_LITERAL, STRING_LITERAL, TEXT_BLOCK,
        PACKAGE, IMPORT, STATIC, FINAL, PUBLIC, PROTECTED, PRIVATE, ABSTRACT, NATIVE,
        SYNCHRONIZED, TRANSIENT, VOLATILE, DEFAULT, CLASS, INTERFACE, ENUM, EXTENDS,
        IMPLEMENTS, THROWS, THROW, RETURN, IF, ELSE, WHILE, DO, FOR, SWITCH, CASE,
        BREAK, CONTINUE, TRY, CATCH, FINALLY, NEW, THIS, SUPER, INSTANCEOF,
        TRUE, FALSE, NULL, VOID, BOOLEAN, INT, LONG, SHORT, BYTE, CHAR, FLOAT, DOUBLE,
        ASSERT, SEALED, NON_SEALED, PERMITS, YIELD, RECORD,
        LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET,
        SEMI, COMMA, DOT, ELLIPSIS, AT, COLON, COLONCOLON, QUESTION, ARROW,
        ASSIGN, PLUS, MINUS, STAR, SLASH, PERCENT, AMP, PIPE, CARET, BANG, TILDE,
        LT, GT, LE, GE, EQ, NE, AND, OR, INC, DEC,
        PLUS_ASSIGN, MINUS_ASSIGN, STAR_ASSIGN, SLASH_ASSIGN, PERCENT_ASSIGN,
        AMP_ASSIGN, PIPE_ASSIGN, CARET_ASSIGN, SHL_ASSIGN, SHR_ASSIGN, USHR_ASSIGN,
        SHL, SHR, USHR,
        EOF
    }

    public record Token(TokenKind kind, String text, int line) {
    }

    private static final Map<String, TokenKind> KEYWORDS = keywords();

    public List<Token> tokenize(String file, String source) {
        Scanner s = new Scanner(file, source);
        List<Token> tokens = new ArrayList<>();
        while (s.i < s.n) {
            char c = source.charAt(s.i);
            if (c == '\n') {
                s.line++;
                s.i++;
            } else if (Character.isWhitespace(c)) {
                s.i++;
            } else if (c == '/' && s.peek(1) == '/') {
                s.skipLineComment();
            } else if (c == '/' && s.peek(1) == '*') {
                s.skipBlockComment();
            } else if (Character.isJavaIdentifierStart(c)) {
                s.readIdentifier(tokens);
            } else if (c == '"') {
                s.readString(tokens);
            } else if (c == '\'') {
                s.readCharLiteral(tokens);
            } else if (Character.isDigit(c) || (c == '.' && Character.isDigit(s.peek(1)))) {
                s.readNumber(tokens);
            } else {
                s.readOperator(tokens);
            }
        }
        tokens.add(new Token(TokenKind.EOF, "", s.line));
        return tokens;
    }

    private static Map<String, TokenKind> keywords() {
        Map<String, TokenKind> k = new HashMap<>();
        k.put("package", TokenKind.PACKAGE);
        k.put("import", TokenKind.IMPORT);
        k.put("static", TokenKind.STATIC);
        k.put("final", TokenKind.FINAL);
        k.put("public", TokenKind.PUBLIC);
        k.put("protected", TokenKind.PROTECTED);
        k.put("private", TokenKind.PRIVATE);
        k.put("abstract", TokenKind.ABSTRACT);
        k.put("native", TokenKind.NATIVE);
        k.put("synchronized", TokenKind.SYNCHRONIZED);
        k.put("transient", TokenKind.TRANSIENT);
        k.put("volatile", TokenKind.VOLATILE);
        k.put("default", TokenKind.DEFAULT);
        k.put("class", TokenKind.CLASS);
        k.put("interface", TokenKind.INTERFACE);
        k.put("enum", TokenKind.ENUM);
        k.put("extends", TokenKind.EXTENDS);
        k.put("implements", TokenKind.IMPLEMENTS);
        k.put("throws", TokenKind.THROWS);
        k.put("throw", TokenKind.THROW);
        k.put("return", TokenKind.RETURN);
        k.put("if", TokenKind.IF);
        k.put("else", TokenKind.ELSE);
        k.put("while", TokenKind.WHILE);
        k.put("do", TokenKind.DO);
        k.put("for", TokenKind.FOR);
        k.put("switch", TokenKind.SWITCH);
        k.put("case", TokenKind.CASE);
        k.put("break", TokenKind.BREAK);
        k.put("continue", TokenKind.CONTINUE);
        k.put("try", TokenKind.TRY);
        k.put("catch", TokenKind.CATCH);
        k.put("finally", TokenKind.FINALLY);
        k.put("new", TokenKind.NEW);
        k.put("this", TokenKind.THIS);
        k.put("super", TokenKind.SUPER);
        k.put("instanceof", TokenKind.INSTANCEOF);
        k.put("true", TokenKind.TRUE);
        k.put("false", TokenKind.FALSE);
        k.put("null", TokenKind.NULL);
        k.put("void", TokenKind.VOID);
        k.put("boolean", TokenKind.BOOLEAN);
        k.put("int", TokenKind.INT);
        k.put("long", TokenKind.LONG);
        k.put("short", TokenKind.SHORT);
        k.put("byte", TokenKind.BYTE);
        k.put("char", TokenKind.CHAR);
        k.put("float", TokenKind.FLOAT);
        k.put("double", TokenKind.DOUBLE);
        k.put("assert", TokenKind.ASSERT);
        k.put("sealed", TokenKind.SEALED);
        k.put("non-sealed", TokenKind.NON_SEALED);
        k.put("permits", TokenKind.PERMITS);
        k.put("yield", TokenKind.YIELD);
        k.put("record", TokenKind.RECORD);
        return Map.copyOf(k);
    }

    private static final class Scanner {
        private final String file;
        private final String source;
        private int i;
        private final int n;
        private int line = 1;

        private Scanner(String file, String source) {
            this.file = file;
            this.source = source;
            this.n = source.length();
        }

        private char peek(int offset) {
            int p = i + offset;
            return p >= 0 && p < n ? source.charAt(p) : '\0';
        }

        private JavaParseException error(JavaParseException.Reason reason, String message) {
            return new JavaParseException(file, line, reason, message);
        }

        private void skipLineComment() {
            i += 2;
            while (i < n && source.charAt(i) != '\n') {
                i++;
            }
        }

        private void skipBlockComment() {
            int startLine = line;
            i += 2;
            while (i < n && !(source.charAt(i) == '*' && peek(1) == '/')) {
                if (source.charAt(i) == '\n') {
                    line++;
                }
                i++;
            }
            if (i >= n) {
                throw new JavaParseException(file, startLine, JavaParseException.Reason.LEXICAL,
                        "unterminated block comment");
            }
            i += 2;
        }

        private void readIdentifier(List<Token> tokens) {
            int start = i;
            while (i < n && Character.isJavaIdentifierPart(source.charAt(i))) {
                i++;
            }
            String word = source.substring(start, i);
            tokens.add(new Token(KEYWORDS.getOrDefault(word, TokenKind.IDENT), word, line));
        }

        private void readString(List<Token> tokens) {
            int startLine = line;
            if (peek(1) == '"' && peek(2) == '"') {
                i += 3;
                while (i < n) {
                    if (source.charAt(i) == '\\') {
                        skipEscape();
                        continue;
                    }
                    if (source.charAt(i) == '"' && peek(1) == '"' && peek(2) == '"') {
                        i += 3;
                        tokens.add(new Token(TokenKind.TEXT_BLOCK, "", startLine));
                        return;
                    }
                    if (source.charAt(i) == '\n') {
                        line++;
                    }
                    i++;
                }
                throw new JavaParseException(file, startLine, JavaParseException.Reason.LEXICAL,
                        "unterminated text block");
            }
            i++;
            while (i < n && source.charAt(i) != '"') {
                if (source.charAt(i) == '\n') {
                    throw error(JavaParseException.Reason.LEXICAL, "newline inside string literal");
                }
                if (source.charAt(i) == '\\') {
                    skipEscape();
                    continue;
                }
                i++;
            }
            if (i >= n) {
                throw error(JavaParseException.Reason.LEXICAL, "unterminated string literal");
            }
            i++;
            tokens.add(new Token(TokenKind.STRING_LITERAL, "", startLine));
        }

        private void readCharLiteral(List<Token> tokens) {
            int startLine = line;
            i++;
            if (i < n && source.charAt(i) == '\\') {
                skipEscape();
            } else if (i < n) {
                i++;
            }
            if (i >= n || source.charAt(i) != '\'') {
                throw new JavaParseException(file, startLine, JavaParseException.Reason.LEXICAL,
                        "unterminated character literal");
            }
            i++;
            tokens.add(new Token(TokenKind.CHAR_LITERAL, "", startLine));
        }

        private void skipEscape() {
            int startLine = line;
            i++; // backslash
            if (i >= n) {
                throw new JavaParseException(file, startLine, JavaParseException.Reason.LEXICAL,
                        "dangling escape");
            }
            char c = source.charAt(i);
            if (c == '\n') {
                line++;
            }
            i++;
            if (c == 'u') {
                for (int d = 0; d < 4; d++, i++) {
                    if (i >= n || Character.digit(source.charAt(i), 16) < 0) {
                        throw new JavaParseException(file, line, JavaParseException.Reason.LEXICAL,
                                "bad unicode escape");
                    }
                }
            } else if (c >= '0' && c <= '7') {
                for (int d = 0; d < 2 && i < n && Character.isDigit(source.charAt(i)); d++) {
                    i++;
                }
            }
        }

        private void readNumber(List<Token> tokens) {
            int startLine = line;
            boolean floating = false;
            if (source.charAt(i) == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
                i += 2;
                while (i < n && (isHex(source.charAt(i)) || source.charAt(i) == '_'
                        || source.charAt(i) == '.' || source.charAt(i) == 'p' || source.charAt(i) == 'P'
                        || ((source.charAt(i) == '+' || source.charAt(i) == '-')
                        && (source.charAt(i - 1) == 'p' || source.charAt(i - 1) == 'P')))) {
                    char c = source.charAt(i);
                    if (c == '.' || c == 'p' || c == 'P') {
                        floating = true;
                    }
                    i++;
                }
            } else {
                while (i < n && (Character.isDigit(source.charAt(i)) || source.charAt(i) == '_')) {
                    i++;
                }
                if (i < n && source.charAt(i) == '.') {
                    floating = true;
                    i++;
                    while (i < n && (Character.isDigit(source.charAt(i)) || source.charAt(i) == '_')) {
                        i++;
                    }
                }
                if (i < n && (source.charAt(i) == 'e' || source.charAt(i) == 'E')) {
                    floating = true;
                    i++;
                    if (i < n && (source.charAt(i) == '+' || source.charAt(i) == '-')) {
                        i++;
                    }
                    while (i < n && Character.isDigit(source.charAt(i))) {
                        i++;
                    }
                }
            }
            if (i < n && (source.charAt(i) == 'f' || source.charAt(i) == 'F')) {
                floating = true;
                i++;
            } else if (i < n && (source.charAt(i) == 'd' || source.charAt(i) == 'D'
                    || source.charAt(i) == 'l' || source.charAt(i) == 'L')) {
                i++;
            }
            tokens.add(new Token(floating ? TokenKind.FLOAT_LITERAL : TokenKind.INT_LITERAL, "", startLine));
        }

        private static boolean isHex(char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        private void readOperator(List<Token> tokens) {
            int startLine = line;
            char c = source.charAt(i);
            TokenKind kind;
            int len = 1;
            switch (c) {
                case '(' -> kind = TokenKind.LPAREN;
                case ')' -> kind = TokenKind.RPAREN;
                case '{' -> kind = TokenKind.LBRACE;
                case '}' -> kind = TokenKind.RBRACE;
                case '[' -> kind = TokenKind.LBRACKET;
                case ']' -> kind = TokenKind.RBRACKET;
                case ';' -> kind = TokenKind.SEMI;
                case ',' -> kind = TokenKind.COMMA;
                case '@' -> kind = TokenKind.AT;
                case '~' -> kind = TokenKind.TILDE;
                case '.' -> {
                    if (peek(1) == '.' && peek(2) == '.') {
                        kind = TokenKind.ELLIPSIS;
                        len = 3;
                    } else {
                        kind = TokenKind.DOT;
                    }
                }
                case ':' -> {
                    if (peek(1) == ':') {
                        kind = TokenKind.COLONCOLON;
                        len = 2;
                    } else {
                        kind = TokenKind.COLON;
                    }
                }
                case '?' -> kind = TokenKind.QUESTION;
                case '+' -> {
                    if (peek(1) == '+') {
                        kind = TokenKind.INC;
                        len = 2;
                    } else if (peek(1) == '=') {
                        kind = TokenKind.PLUS_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.PLUS;
                    }
                }
                case '-' -> {
                    if (peek(1) == '>') {
                        kind = TokenKind.ARROW;
                        len = 2;
                    } else if (peek(1) == '-') {
                        kind = TokenKind.DEC;
                        len = 2;
                    } else if (peek(1) == '=') {
                        kind = TokenKind.MINUS_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.MINUS;
                    }
                }
                case '*' -> {
                    if (peek(1) == '=') {
                        kind = TokenKind.STAR_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.STAR;
                    }
                }
                case '/' -> {
                    if (peek(1) == '=') {
                        kind = TokenKind.SLASH_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.SLASH;
                    }
                }
                case '%' -> {
                    if (peek(1) == '=') {
                        kind = TokenKind.PERCENT_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.PERCENT;
                    }
                }
                case '&' -> {
                    if (peek(1) == '&') {
                        kind = TokenKind.AND;
                        len = 2;
                    } else if (peek(1) == '=') {
                        kind = TokenKind.AMP_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.AMP;
                    }
                }
                case '|' -> {
                    if (peek(1) == '|') {
                        kind = TokenKind.OR;
                        len = 2;
                    } else if (peek(1) == '=') {
                        kind = TokenKind.PIPE_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.PIPE;
                    }
                }
                case '^' -> {
                    if (peek(1) == '=') {
                        kind = TokenKind.CARET_ASSIGN;
                        len = 2;
                    } else {
                        kind = TokenKind.CARET;
                    }
                }
                case '!' -> {
                    if (peek(1) == '=') {
                        kind = TokenKind.NE;
                        len = 2;
                    } else {
                        kind = TokenKind.BANG;
                    }
                }
                case '=' -> {
                    if (peek(1) == '=') {
                        kind = TokenKind.EQ;
                        len = 2;
                    } else {
                        kind = TokenKind.ASSIGN;
                    }
                }
                case '<' -> {
                    if (peek(1) == '<') {
                        if (peek(2) == '=') {
                            kind = TokenKind.SHL_ASSIGN;
                            len = 3;
                        } else {
                            kind = TokenKind.SHL;
                            len = 2;
                        }
                    } else if (peek(1) == '=') {
                        kind = TokenKind.LE;
                        len = 2;
                    } else {
                        kind = TokenKind.LT;
                    }
                }
                case '>' -> {
                    if (peek(1) == '>') {
                        if (peek(2) == '>') {
                            len = peek(3) == '=' ? 4 : 3;
                            kind = len == 4 ? TokenKind.USHR_ASSIGN : TokenKind.USHR;
                        } else if (peek(2) == '=') {
                            kind = TokenKind.SHR_ASSIGN;
                            len = 3;
                        } else {
                            kind = TokenKind.SHR;
                            len = 2;
                        }
                    } else if (peek(1) == '=') {
                        kind = TokenKind.GE;
                        len = 2;
                    } else {
                        kind = TokenKind.GT;
                    }
                }
                default -> throw new JavaParseException(file, line, JavaParseException.Reason.LEXICAL,
                        "unexpected character '" + c + "'");
            }
            tokens.add(new Token(kind, source.substring(i, i + len), startLine));
            i += len;
        }
    }
}
