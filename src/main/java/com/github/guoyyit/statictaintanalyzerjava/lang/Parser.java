package com.github.guoyyit.statictaintanalyzerjava.lang;

import com.github.guoyyit.statictaintanalyzerjava.lang.Lexer.Token;
import com.github.guoyyit.statictaintanalyzerjava.lang.Lexer.TokenKind;

import java.util.ArrayList;
import java.util.List;

/**
 * Recursive-descent parser producing {@link Ast.Program}.
 *
 * Grammar:
 *   program  := function*
 *   function := 'fn' IDENT '(' params? ')' block
 *   stmt     := 'return' expr ';' | 'if' '(' expr ')' block ('else' block)?
 *             | 'while' '(' expr ')' block | IDENT '=' expr ';' | expr ';'
 *   expr     := primary ('+' primary)*
 *   primary  := IDENT ('(' args? ')')? | STRING | NUMBER | '(' expr ')'
 */
public final class Parser {

    private final Lexer lexer = new Lexer();

    private List<Token> tokens;
    private int pos;
    private String fileName;

    public Ast.Program parse(String fileName, String source) {
        this.tokens = lexer.tokenize(source);
        this.pos = 0;
        this.fileName = fileName;
        List<Ast.FunctionDef> functions = new ArrayList<>();
        while (peek().kind() != TokenKind.EOF) {
            functions.add(parseFunction());
        }
        return new Ast.Program(List.copyOf(functions));
    }

    private Ast.FunctionDef parseFunction() {
        Token fn = expect(TokenKind.FN);
        Token name = expect(TokenKind.IDENT);
        expect(TokenKind.LPAREN);
        List<String> params = new ArrayList<>();
        if (peek().kind() != TokenKind.RPAREN) {
            params.add(expect(TokenKind.IDENT).text());
            while (peek().kind() == TokenKind.COMMA) {
                advance();
                params.add(expect(TokenKind.IDENT).text());
            }
        }
        expect(TokenKind.RPAREN);
        List<Ast.Stmt> body = parseBlock();
        return new Ast.FunctionDef(name.text(), List.copyOf(params), body, fileName, fn.line());
    }

    private List<Ast.Stmt> parseBlock() {
        expect(TokenKind.LBRACE);
        List<Ast.Stmt> stmts = new ArrayList<>();
        while (peek().kind() != TokenKind.RBRACE) {
            stmts.add(parseStmt());
        }
        expect(TokenKind.RBRACE);
        return List.copyOf(stmts);
    }

    private Ast.Stmt parseStmt() {
        Token t = peek();
        switch (t.kind()) {
            case RETURN -> {
                advance();
                Ast.Expr value = parseExpr();
                expect(TokenKind.SEMI);
                return new Ast.Return(value, t.line());
            }
            case IF -> {
                advance();
                expect(TokenKind.LPAREN);
                Ast.Expr cond = parseExpr();
                expect(TokenKind.RPAREN);
                List<Ast.Stmt> thenBody = parseBlock();
                List<Ast.Stmt> elseBody = List.of();
                if (peek().kind() == TokenKind.ELSE) {
                    advance();
                    elseBody = parseBlock();
                }
                return new Ast.If(cond, thenBody, elseBody, t.line());
            }
            case WHILE -> {
                advance();
                expect(TokenKind.LPAREN);
                Ast.Expr cond = parseExpr();
                expect(TokenKind.RPAREN);
                List<Ast.Stmt> body = parseBlock();
                return new Ast.While(cond, body, t.line());
            }
            case IDENT -> {
                if (peekAt(1).kind() == TokenKind.ASSIGN) {
                    advance();
                    advance();
                    Ast.Expr value = parseExpr();
                    expect(TokenKind.SEMI);
                    return new Ast.Assign(t.text(), value, t.line());
                }
                Ast.Expr expr = parseExpr();
                expect(TokenKind.SEMI);
                return new Ast.ExprStmt(expr, t.line());
            }
            default -> throw error("unexpected statement start: " + t.kind());
        }
    }

    private Ast.Expr parseExpr() {
        Ast.Expr left = parsePrimary();
        while (peek().kind() == TokenKind.PLUS) {
            Token op = advance();
            Ast.Expr right = parsePrimary();
            left = new Ast.Binary("+", left, right, op.line());
        }
        return left;
    }

    private Ast.Expr parsePrimary() {
        Token t = peek();
        switch (t.kind()) {
            case IDENT -> {
                advance();
                if (peek().kind() == TokenKind.LPAREN) {
                    advance();
                    List<Ast.Expr> args = new ArrayList<>();
                    if (peek().kind() != TokenKind.RPAREN) {
                        args.add(parseExpr());
                        while (peek().kind() == TokenKind.COMMA) {
                            advance();
                            args.add(parseExpr());
                        }
                    }
                    expect(TokenKind.RPAREN);
                    return new Ast.Call(t.text(), List.copyOf(args), t.line());
                }
                return new Ast.Ident(t.text(), t.line());
            }
            case STRING, NUMBER -> {
                advance();
                return new Ast.Literal(t.text(), t.line());
            }
            case LPAREN -> {
                advance();
                Ast.Expr inner = parseExpr();
                expect(TokenKind.RPAREN);
                return inner;
            }
            default -> throw error("unexpected expression start: " + t.kind());
        }
    }

    private Token peek() {
        return tokens.get(pos);
    }

    private Token peekAt(int offset) {
        return tokens.get(Math.min(pos + offset, tokens.size() - 1));
    }

    private Token advance() {
        return tokens.get(pos++);
    }

    private Token expect(TokenKind kind) {
        Token t = peek();
        if (t.kind() != kind) {
            throw error("expected " + kind + " but got " + t.kind() + " ('" + t.text() + "')");
        }
        return advance();
    }

    private Lexer.ParseException error(String message) {
        return new Lexer.ParseException(message + " at line " + peek().line() + " in " + fileName);
    }
}
