package com.github.guoyyit.statictaintanalyzerjava.lang;

import java.util.ArrayList;
import java.util.List;

/**
 * Tokenizer for the analyzed DSL. Deterministic, no backtracking.
 */
public final class Lexer {

    public enum TokenKind {
        IDENT, STRING, NUMBER,
        FN, IF, ELSE, WHILE, RETURN,
        LPAREN, RPAREN, LBRACE, RBRACE, SEMI, ASSIGN, PLUS, COMMA,
        EOF
    }

    public record Token(TokenKind kind, String text, int line) {
    }

    public List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int line = 1;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (c == '\n') {
                line++;
                i++;
                continue;
            }
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }
            if (Character.isLetter(c) || c == '_') {
                int start = i;
                while (i < n && (Character.isLetterOrDigit(source.charAt(i)) || source.charAt(i) == '_')) {
                    i++;
                }
                String word = source.substring(start, i);
                tokens.add(new Token(keywordOf(word), word, line));
                continue;
            }
            if (Character.isDigit(c)) {
                int start = i;
                while (i < n && Character.isDigit(source.charAt(i))) {
                    i++;
                }
                tokens.add(new Token(TokenKind.NUMBER, source.substring(start, i), line));
                continue;
            }
            if (c == '"') {
                StringBuilder sb = new StringBuilder();
                i++;
                while (i < n && source.charAt(i) != '"') {
                    if (source.charAt(i) == '\\' && i + 1 < n) {
                        i++;
                    }
                    sb.append(source.charAt(i));
                    i++;
                }
                if (i >= n) {
                    throw new ParseException("unterminated string at line " + line);
                }
                i++; // closing quote
                tokens.add(new Token(TokenKind.STRING, sb.toString(), line));
                continue;
            }
            switch (c) {
                case '(' -> tokens.add(new Token(TokenKind.LPAREN, "(", line));
                case ')' -> tokens.add(new Token(TokenKind.RPAREN, ")", line));
                case '{' -> tokens.add(new Token(TokenKind.LBRACE, "{", line));
                case '}' -> tokens.add(new Token(TokenKind.RBRACE, "}", line));
                case ';' -> tokens.add(new Token(TokenKind.SEMI, ";", line));
                case '=' -> tokens.add(new Token(TokenKind.ASSIGN, "=", line));
                case '+' -> tokens.add(new Token(TokenKind.PLUS, "+", line));
                case ',' -> tokens.add(new Token(TokenKind.COMMA, ",", line));
                default -> throw new ParseException("unexpected character '" + c + "' at line " + line);
            }
            i++;
        }
        tokens.add(new Token(TokenKind.EOF, "", line));
        return tokens;
    }

    private static TokenKind keywordOf(String word) {
        return switch (word) {
            case "fn" -> TokenKind.FN;
            case "if" -> TokenKind.IF;
            case "else" -> TokenKind.ELSE;
            case "while" -> TokenKind.WHILE;
            case "return" -> TokenKind.RETURN;
            default -> TokenKind.IDENT;
        };
    }

    public static final class ParseException extends RuntimeException {
        public ParseException(String message) {
            super(message);
        }
    }
}
