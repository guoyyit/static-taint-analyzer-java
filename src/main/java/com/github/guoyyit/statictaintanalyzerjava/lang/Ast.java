package com.github.guoyyit.statictaintanalyzerjava.lang;

import java.util.List;

/**
 * AST node definitions for the analyzed DSL. Pure type definitions, no logic.
 */
public final class Ast {

    private Ast() {
    }

    public record Program(List<FunctionDef> functions) {
    }

    public record FunctionDef(String name, List<String> params, List<Stmt> body, String file, int line) {
    }

    public sealed interface Stmt permits Assign, ExprStmt, Return, If, While {
    }

    public record Assign(String target, Expr value, int line) implements Stmt {
    }

    public record ExprStmt(Expr expr, int line) implements Stmt {
    }

    public record Return(Expr value, int line) implements Stmt {
    }

    public record If(Expr cond, List<Stmt> thenBody, List<Stmt> elseBody, int line) implements Stmt {
    }

    public record While(Expr cond, List<Stmt> body, int line) implements Stmt {
    }

    public sealed interface Expr permits Ident, Literal, Call, Binary {
    }

    public record Ident(String name, int line) implements Expr {
    }

    public record Literal(String value, int line) implements Expr {
    }

    public record Call(String callee, List<Expr> args, int line) implements Expr {
    }

    public record Binary(String op, Expr left, Expr right, int line) implements Expr {
    }
}
