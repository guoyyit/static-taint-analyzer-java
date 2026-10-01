package com.github.guoyyit.statictaintanalyzerjava.lang.java;

import java.util.List;

/**
 * AST for the subset of real Java source understood by the analyzer.
 * Pure type definitions; the parser produces these nodes and the analysis
 * layer consumes them. Nodes carry their source file and 1-based line.
 */
public final class JavaAst {

    private JavaAst() {
    }

    /** One .java file: optional package, imports and top-level type declarations. */
    public record CompilationUnit(String file,
                                  String packageName,
                                  List<String> imports,
                                  List<TypeDecl> types,
                                  int line) {
    }

    /** Class, interface, enum or annotation type declaration. */
    public record TypeDecl(String name,
                           String kind,
                           String packageName,
                           List<String> extendsNames,
                           List<String> implementsNames,
                           List<TypeDecl> nested,
                           List<Member> members,
                           List<String> modifiers,
                           boolean isStatic,
                           String file,
                           int line) {

        public boolean isInterface() {
            return "interface".equals(kind);
        }

        /** Fully qualified dot name, e.g. {@code com.acme.Web.UserService}. */
        public String qualifiedName() {
            return packageName == null || packageName.isEmpty() ? name : packageName + "." + name;
        }
    }

    /** A type member: method, constructor, field or initializer block. */
    public sealed interface Member permits MethodDecl, FieldDecl, InitBlock, NestedTypeMember {
        String file();

        int line();
    }

    public record MethodDecl(String name,
                             String returnType,
                             List<Param> params,
                             List<Stmt> body,
                             List<String> modifiers,
                             boolean isStatic,
                             boolean isConstructor,
                             String ownerQualifiedName,
                             String file,
                             int line) implements Member {
        public boolean isStaticOrCtor() {
            return isStatic || isConstructor;
        }
    }

    /** A single field declaration group: {@code static int a = 1, b = 2;}. */
    public record FieldDecl(String type,
                            List<VariableDeclarator> declarators,
                            boolean isStatic,
                            String ownerQualifiedName,
                            String file,
                            int line) implements Member {
    }

    public record InitBlock(List<Stmt> body, boolean isStatic, String file, int line) implements Member {
    }

    public record NestedTypeMember(TypeDecl type) implements Member {
        @Override
        public String file() {
            return type.file();
        }

        @Override
        public int line() {
            return type.line();
        }
    }

    public record Param(String name, String type, boolean isThis) {
    }

    public record VariableDeclarator(String name, Expr initializer, int line) {
    }

    // ---------------------------------------------------------------- statements

    public sealed interface Stmt
            permits LocalVarStmt, ExpressionStmt, ReturnStmt, ThrowStmt,
            IfStmt, WhileStmt, DoWhileStmt, ForStmt, EnhancedForStmt, BlockStmt,
            BreakStmt, ContinueStmt, TryStmt, SwitchStmt, LabeledStmt, SynchronizedStmt,
            AssertStmt, EmptyStmt {
        int line();
    }

    /** One declarator inside a local variable declaration. */
    public record VarDecl(String name, String type, Expr initializer, int line) {
    }

    public record LocalVarStmt(List<VarDecl> declarators, int line) implements Stmt {
    }

    public record ExpressionStmt(Expr expr, int line) implements Stmt {
    }

    public record ReturnStmt(Expr value, int line) implements Stmt {
    }

    public record ThrowStmt(Expr value, int line) implements Stmt {
    }

    public record IfStmt(Expr cond, List<Stmt> thenBody, List<Stmt> elseBody, int line) implements Stmt {
    }

    public record WhileStmt(Expr cond, List<Stmt> body, int line) implements Stmt {
    }

    public record DoWhileStmt(Expr cond, List<Stmt> body, int line) implements Stmt {
    }

    /** Traditional C-style for loop; each clause is optional and may declare locals. */
    public record ForStmt(List<Stmt> init, Expr cond, List<Expr> update,
                          List<Stmt> body, int line) implements Stmt {
    }

    public record EnhancedForStmt(String varName, String varType, Expr iterable,
                                  List<Stmt> body, int line) implements Stmt {
    }

    public record BlockStmt(List<Stmt> body, int line) implements Stmt {
    }

    public record BreakStmt(String label, int line) implements Stmt {
    }

    public record ContinueStmt(String label, int line) implements Stmt {
    }

    public record CatchClause(String param, String paramType, List<Stmt> body, int line) {
    }

    public record TryStmt(List<Stmt> resources, List<Stmt> body,
                          List<CatchClause> catchClauses, List<Stmt> finallyBody, int line) implements Stmt {
    }

    public record SwitchCase(List<Expr> labels, boolean isDefault, List<Stmt> body, int line) {
    }

    public record SwitchStmt(Expr selector, List<SwitchCase> cases, int line) implements Stmt {
    }

    public record LabeledStmt(String label, Stmt body, int line) implements Stmt {
    }

    public record SynchronizedStmt(Expr monitor, List<Stmt> body, int line) implements Stmt {
    }

    public record AssertStmt(Expr condition, Expr detail, int line) implements Stmt {
    }

    public record EmptyStmt(int line) implements Stmt {
    }

    // -------------------------------------------------------------- expressions

    public sealed interface Expr
            permits LiteralExpr, IdentExpr, ThisExpr, SuperExpr, FieldAccessExpr,
            CallExpr, NewExpr, NewArrayExpr, ArrayAccessExpr, ArrayInitExpr,
            AssignExpr, BinaryExpr, UnaryExpr, CastExpr, InstanceOfExpr,
            ConditionalExpr, ParenExpr, LambdaExpr, MethodRefExpr {
        int line();
    }

    public record LiteralExpr(String value, String kind, int line) implements Expr {
    }

    /** Simple local identifier; qualified names are chains of {@link FieldAccessExpr}. */
    public record IdentExpr(String name, int line) implements Expr {
    }

    public record ThisExpr(String qualifier, int line) implements Expr {
    }

    public record SuperExpr(String qualifier, int line) implements Expr {
    }

    /**
     * Any postfix selection: {@code a.b}, {@code pkg.Cls}, {@code obj.field},
     * or a qualified call target when {@code target} is the receiver of a call.
     */
    public record FieldAccessExpr(Expr target, String name, int line) implements Expr {
    }

    /**
     * Method invocation. {@code target} is null for a simple call; otherwise it
     * is the receiver expression (ident, field access, this/super, ...).
     */
    public record CallExpr(Expr target, String name, List<Expr> args, int line) implements Expr {
    }

    public record NewExpr(String typeName, List<Expr> args, Expr enclosing,
                          TypeDecl anonymousBody, int line) implements Expr {
    }

    public record NewArrayExpr(String typeName, List<Expr> dimensions,
                               List<Expr> initializer, int line) implements Expr {
    }

    public record ArrayAccessExpr(Expr array, Expr index, int line) implements Expr {
    }

    public record ArrayInitExpr(List<Expr> elements, int line) implements Expr {
    }

    public record AssignExpr(String op, Expr target, Expr value, int line) implements Expr {
    }

    public record BinaryExpr(String op, Expr left, Expr right, int line) implements Expr {
    }

    public record UnaryExpr(String op, Expr operand, boolean prefix, int line) implements Expr {
    }

    public record CastExpr(String typeName, Expr operand, int line) implements Expr {
    }

    public record InstanceOfExpr(Expr value, String typeName, String bindingVar, int line) implements Expr {
    }

    public record ConditionalExpr(Expr condition, Expr thenValue, Expr elseValue, int line) implements Expr {
    }

    public record ParenExpr(Expr inner, int line) implements Expr {
    }

    public record LambdaExpr(List<String> params, List<Stmt> body, Expr exprBody, int line) implements Expr {
    }

    public record MethodRefExpr(Expr qualifier, String name, boolean isNew, int line) implements Expr {
    }
}
