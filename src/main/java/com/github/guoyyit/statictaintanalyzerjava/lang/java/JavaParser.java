package com.github.guoyyit.statictaintanalyzerjava.lang.java;

import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaLexer.Token;
import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaLexer.TokenKind;

import java.util.ArrayList;
import java.util.List;

/**
 * Recursive-descent parser for the supported Java subset. Produces a
 * {@link JavaAst.CompilationUnit}; throws {@link JavaParseException} carrying
 * file, line and {@link JavaParseException.Reason}.
 */
public final class JavaParser {

    private final JavaLexer lexer = new JavaLexer();

    private List<Token> tokens;
    private int pos;
    private String file;

    public JavaAst.CompilationUnit parse(String fileName, String source) {
        this.file = fileName;
        this.tokens = lexer.tokenize(fileName, source);
        this.pos = 0;
        int line = peek().line();
        String packageName = "";
        List<String> imports = new ArrayList<>();
        if (check(TokenKind.PACKAGE)) {
            line = peek().line();
            advance();
            packageName = readDottedName();
            expect(TokenKind.SEMI);
        }
        while (check(TokenKind.IMPORT)) {
            advance();
            boolean isStatic = match(TokenKind.STATIC);
            String name = readDottedName();
            expect(TokenKind.SEMI);
            imports.add((isStatic ? "static " : "") + name);
        }
        List<JavaAst.TypeDecl> types = new ArrayList<>();
        while (!atEnd()) {
            while (match(TokenKind.SEMI)) {
                // stray semicolons between declarations
            }
            if (atEnd()) {
                break;
            }
            types.add(parseTypeDecl(packageName));
        }
        return new JavaAst.CompilationUnit(file, packageName, List.copyOf(imports),
                List.copyOf(types), line);
    }

    // ------------------------------------------------------------- types

    private JavaAst.TypeDecl parseTypeDecl(String packageName) {
        List<String> modifiers = parseModifiers();
        boolean isStatic = modifiers.contains("static");
        Token keyword = peek();
        return switch (keyword.kind()) {
            case CLASS, INTERFACE -> parseClassLike(packageName, modifiers, isStatic,
                    keyword.kind() == TokenKind.CLASS ? "class" : "interface");
            case ENUM -> parseEnum(packageName, modifiers, isStatic);
            case RECORD -> parseRecord(packageName, modifiers, isStatic);
            case AT -> {
                advance();
                expect(TokenKind.INTERFACE);
                expect(TokenKind.IDENT);
                skipTypeHeaderSuffix();
                skipBalancedBraces();
                yield new JavaAst.TypeDecl("", "@interface", packageName,
                        List.of(), List.of(), List.of(), List.of(), modifiers, isStatic,
                        file, keyword.line());
            }
            default -> throw syntax("expected type declaration but found '" + keyword.text() + "'");
        };
    }

    private JavaAst.TypeDecl parseClassLike(String packageName, List<String> modifiers,
                                            boolean isStatic, String kind) {
        int line = advance().line();
        String name = expect(TokenKind.IDENT).text();
        skipTypeArguments();
        List<String> extendsNames = new ArrayList<>();
        List<String> implementsNames = new ArrayList<>();
        if (match(TokenKind.EXTENDS)) {
            extendsNames.add(readTypeName());
            while (match(TokenKind.COMMA)) {
                extendsNames.add(readTypeName());
            }
        }
        if (match(TokenKind.IMPLEMENTS)) {
            implementsNames.add(readTypeName());
            while (match(TokenKind.COMMA)) {
                implementsNames.add(readTypeName());
            }
        }
        if (match(TokenKind.PERMITS)) {
            readTypeName();
            while (match(TokenKind.COMMA)) {
                readTypeName();
            }
        }
        expect(TokenKind.LBRACE);
        List<JavaAst.Member> members = parseMembers(packageName, name);
        expect(TokenKind.RBRACE);
        return new JavaAst.TypeDecl(name, kind, packageName, List.copyOf(extendsNames),
                List.copyOf(implementsNames), List.of(), List.copyOf(members),
                List.copyOf(modifiers), isStatic, file, line);
    }

    private JavaAst.TypeDecl parseEnum(String packageName, List<String> modifiers, boolean isStatic) {
        int line = advance().line();
        String name = expect(TokenKind.IDENT).text();
        if (match(TokenKind.IMPLEMENTS)) {
            readTypeName();
            while (match(TokenKind.COMMA)) {
                readTypeName();
            }
        }
        expect(TokenKind.LBRACE);
        if (!check(TokenKind.SEMI) && !check(TokenKind.RBRACE)) {
            while (true) {
                while (check(TokenKind.AT)) {
                    skipAnnotation();
                }
                if (!check(TokenKind.IDENT)) {
                    break;
                }
                advance(); // constant name
                if (check(TokenKind.LPAREN)) {
                    skipParenthesized();
                }
                if (check(TokenKind.LBRACE)) {
                    skipBalancedBraces();
                }
                if (check(TokenKind.COMMA)) {
                    advance();
                    continue;
                }
                break;
            }
        }
        match(TokenKind.SEMI);
        List<JavaAst.Member> members = parseMembers(packageName, name);
        expect(TokenKind.RBRACE);
        return new JavaAst.TypeDecl(name, "enum", packageName, List.of("java.lang.Enum"),
                List.of(), List.of(), List.copyOf(members), List.copyOf(modifiers), isStatic, file, line);
    }

    private JavaAst.TypeDecl parseRecord(String packageName, List<String> modifiers, boolean isStatic) {
        int line = advance().line();
        String name = expect(TokenKind.IDENT).text();
        skipTypeArguments();
        expect(TokenKind.LPAREN);
        while (!check(TokenKind.RPAREN)) {
            parseModifiers();
            readTypeName();
            expect(TokenKind.IDENT);
            if (!match(TokenKind.COMMA)) {
                break;
            }
        }
        expect(TokenKind.RPAREN);
        if (match(TokenKind.IMPLEMENTS)) {
            readTypeName();
            while (match(TokenKind.COMMA)) {
                readTypeName();
            }
        }
        expect(TokenKind.LBRACE);
        List<JavaAst.Member> members = parseMembers(packageName, name);
        expect(TokenKind.RBRACE);
        return new JavaAst.TypeDecl(name, "record", packageName, List.of(), List.of(),
                List.of(), List.copyOf(members), List.copyOf(modifiers), isStatic, file, line);
    }

    private List<JavaAst.Member> parseMembers(String packageName, String ownerName) {
        String ownerQ = packageName == null || packageName.isEmpty() ? ownerName : packageName + "." + ownerName;
        List<JavaAst.Member> members = new ArrayList<>();
        while (!check(TokenKind.RBRACE) && !atEnd()) {
            if (match(TokenKind.SEMI)) {
                continue;
            }
            List<String> modifiers = parseModifiers();
            TokenKind k = peek().kind();
            if (k == TokenKind.CLASS || k == TokenKind.INTERFACE || k == TokenKind.ENUM
                    || k == TokenKind.RECORD || k == TokenKind.AT) {
                members.add(new JavaAst.NestedTypeMember(parseTypeDecl(ownerQ)));
                continue;
            }
            JavaAst.Member member = parseMemberOrField(ownerQ, modifiers);
            if (member != null) {
                members.add(member);
            }
        }
        return members;
    }

    private JavaAst.Member parseMemberOrField(String ownerQ, List<String> modifiers) {
        boolean isStatic = modifiers.contains("static");
        if (check(TokenKind.LBRACE)) {
            int line = peek().line();
            return new JavaAst.InitBlock(parseBlock(), isStatic, file, line);
        }
        skipTypeArguments(); // generic method parameter list, e.g. <T extends X> T foo(...)
        int line = peek().line();
        String ownerSimple = ownerQ.contains(".") ? ownerQ.substring(ownerQ.lastIndexOf('.') + 1) : ownerQ;
        String first = readTypeName();
        if (check(TokenKind.LPAREN) && equalsSimpleName(first, ownerSimple)) {
            // constructor: OwnerName(params)
            List<JavaAst.Param> ctorParams = parseFormalParams();
            skipThrowsClause();
            List<JavaAst.Stmt> ctorBody = List.of();
            if (check(TokenKind.LBRACE)) {
                ctorBody = parseBlock();
            } else {
                expect(TokenKind.SEMI);
            }
            return new JavaAst.MethodDecl(ownerSimple, ownerQ, List.copyOf(ctorParams),
                    List.copyOf(ctorBody), List.copyOf(modifiers), isStatic, true, ownerQ, file, line);
        }
        Token nameTok = expect(TokenKind.IDENT);
        if (check(TokenKind.LPAREN)) {
            // regular method: returnType name(params)
            List<JavaAst.Param> params = parseFormalParams();
            skipThrowsClause();
            List<JavaAst.Stmt> body = List.of();
            if (check(TokenKind.LBRACE)) {
                body = parseBlock();
            } else {
                expect(TokenKind.SEMI);
            }
            return new JavaAst.MethodDecl(nameTok.text(), first, List.copyOf(params),
                    List.copyOf(body), List.copyOf(modifiers), isStatic, false,
                    ownerQ, file, line);
        }
        // field declaration group: type d1, d2;
        List<JavaAst.VariableDeclarator> declarators = new ArrayList<>();
        declarators.add(parseVariableDeclaratorRest(nameTok.text(), line));
        while (match(TokenKind.COMMA)) {
            declarators.add(parseVariableDeclarator());
        }
        expect(TokenKind.SEMI);
        return new JavaAst.FieldDecl(first, List.copyOf(declarators), isStatic, ownerQ, file, line);
    }

    private static boolean equalsSimpleName(String typeOrName, String ownerSimple) {
        String simple = typeOrName;
        int dot = simple.lastIndexOf('.');
        if (dot >= 0) {
            simple = simple.substring(dot + 1);
        }
        int brackets = simple.indexOf('[');
        if (brackets >= 0) {
            simple = simple.substring(0, brackets);
        }
        return simple.equals(ownerSimple);
    }

    private void skipThrowsClause() {
        if (match(TokenKind.THROWS)) {
            readTypeName();
            while (match(TokenKind.COMMA)) {
                readTypeName();
            }
        }
    }

    private JavaAst.VariableDeclarator parseVariableDeclaratorRest(String name, int line) {
        while (check(TokenKind.LBRACKET)) {
            advance();
            expect(TokenKind.RBRACKET);
        }
        JavaAst.Expr init = null;
        if (match(TokenKind.ASSIGN)) {
            init = check(TokenKind.LBRACE)
                    ? new JavaAst.ArrayInitExpr(parseArrayInitializerElements(), line)
                    : parseExpression();
        }
        return new JavaAst.VariableDeclarator(name, init, line);
    }

    private JavaAst.VariableDeclarator parseVariableDeclarator() {
        String name = expect(TokenKind.IDENT).text();
        int line = peek().line();
        while (check(TokenKind.LBRACKET)) {
            advance();
            expect(TokenKind.RBRACKET);
        }
        JavaAst.Expr init = null;
        if (match(TokenKind.ASSIGN)) {
            init = check(TokenKind.LBRACE)
                    ? new JavaAst.ArrayInitExpr(parseArrayInitializerElements(), line)
                    : parseExpression();
        }
        return new JavaAst.VariableDeclarator(name, init, line);
    }

    private List<JavaAst.Param> parseFormalParams() {
        expect(TokenKind.LPAREN);
        List<JavaAst.Param> params = new ArrayList<>();
        if (!check(TokenKind.RPAREN)) {
            while (true) {
                parseModifiers();
                StringBuilder type = new StringBuilder(readTypeHead());
                skipTypeArguments();
                if (check(TokenKind.ELLIPSIS)) {
                    advance();
                    type.append("...");
                }
                while (check(TokenKind.LBRACKET)) {
                    advance();
                    expect(TokenKind.RBRACKET);
                    type.append("[]");
                }
                String typeName = type.toString();
                if (check(TokenKind.RPAREN)) {
                    // zero-arg weirdness safeguard
                    break;
                }
                String pname = expect(TokenKind.IDENT).text();
                while (check(TokenKind.LBRACKET)) {
                    advance();
                    expect(TokenKind.RBRACKET);
                }
                params.add(new JavaAst.Param(pname, typeName, false));
                if (!match(TokenKind.COMMA)) {
                    break;
                }
            }
        }
        expect(TokenKind.RPAREN);
        return params;
    }

    // -------------------------------------------------------- type utilities

    private List<String> parseModifiers() {
        List<String> modifiers = new ArrayList<>();
        while (true) {
            TokenKind k = peek().kind();
            if (k == TokenKind.AT) {
                skipAnnotation();
            } else if (isModifier(k)) {
                modifiers.add(advance().text());
            } else {
                break;
            }
        }
        return modifiers;
    }

    private static boolean isModifier(TokenKind k) {
        return k == TokenKind.PUBLIC || k == TokenKind.PRIVATE || k == TokenKind.PROTECTED
                || k == TokenKind.STATIC || k == TokenKind.FINAL || k == TokenKind.ABSTRACT
                || k == TokenKind.NATIVE || k == TokenKind.SYNCHRONIZED
                || k == TokenKind.TRANSIENT || k == TokenKind.VOLATILE || k == TokenKind.DEFAULT
                || k == TokenKind.SEALED || k == TokenKind.NON_SEALED;
    }

    private void skipAnnotation() {
        expect(TokenKind.AT);
        if (check(TokenKind.INTERFACE)) {
            return;
        }
        readDottedName();
        if (check(TokenKind.LPAREN)) {
            skipParenthesized();
        }
    }

    private void skipTypeArguments() {
        if (!check(TokenKind.LT)) {
            return;
        }
        int depth = 0;
        do {
            TokenKind k = peek().kind();
            if (k == TokenKind.LT) {
                depth++;
                advance();
            } else if (k == TokenKind.GT) {
                depth--;
                advance();
            } else if (k == TokenKind.GE) {
                depth -= 2;
                advance();
            } else if (k == TokenKind.SHR) {
                depth -= 3;
                advance();
            } else if (k == TokenKind.USHR) {
                depth -= 4;
                advance();
            } else {
                advance();
            }
        } while (depth > 0 && !atEnd());
    }

    private void skipTypeHeaderSuffix() {
        if (check(TokenKind.EXTENDS) || check(TokenKind.IMPLEMENTS) || check(TokenKind.PERMITS)) {
            advance();
            while (!check(TokenKind.LBRACE) && !atEnd()) {
                advance();
            }
        }
        if (!check(TokenKind.LBRACE)) {
            throw syntax("expected class body");
        }
    }

    private void skipBalancedBraces() {
        expect(TokenKind.LBRACE);
        int depth = 1;
        while (depth > 0 && !atEnd()) {
            TokenKind k = peek().kind();
            if (k == TokenKind.LBRACE) {
                depth++;
            } else if (k == TokenKind.RBRACE) {
                depth--;
            }
            advance();
        }
    }

    private void skipParenthesized() {
        expect(TokenKind.LPAREN);
        int depth = 1;
        while (depth > 0 && !atEnd()) {
            TokenKind k = peek().kind();
            if (k == TokenKind.LPAREN) {
                depth++;
            } else if (k == TokenKind.RPAREN) {
                depth--;
            }
            advance();
        }
    }

    /** Reads a possibly qualified primitive/object type name, with generic
     * arguments, array suffixes and varargs skipped/normalized. */
    String readTypeName() {
        StringBuilder sb = new StringBuilder(readTypeHead());
        skipTypeArguments();
        while (check(TokenKind.LBRACKET)) {
            advance();
            expect(TokenKind.RBRACKET);
            sb.append("[]");
        }
        if (check(TokenKind.ELLIPSIS)) {
            advance();
            sb.append("...");
        }
        return sb.toString();
    }

    private String readTypeHead() {
        Token t = peek();
        StringBuilder sb = new StringBuilder();
        if (isTypeStart(t.kind())) {
            sb.append(advance().text());
        } else {
            sb.append(expect(TokenKind.IDENT).text());
        }
        while (check(TokenKind.DOT)) {
            advance();
            if (check(TokenKind.STAR)) {
                advance();
                sb.append(".*");
                break;
            }
            sb.append('.').append(expect(TokenKind.IDENT).text());
        }
        return sb.toString();
    }

    private String readDottedName() {
        StringBuilder sb = new StringBuilder(expect(TokenKind.IDENT).text());
        while (check(TokenKind.DOT)) {
            advance();
            if (check(TokenKind.STAR)) {
                advance();
                sb.append(".*");
                break;
            }
            sb.append('.').append(expect(TokenKind.IDENT).text());
        }
        return sb.toString();
    }

    // ------------------------------------------------------------- primitives

    private List<JavaAst.Stmt> parseBlock() {
        expect(TokenKind.LBRACE);
        List<JavaAst.Stmt> body = new ArrayList<>();
        while (!check(TokenKind.RBRACE) && !atEnd()) {
            body.add(parseStatement());
        }
        expect(TokenKind.RBRACE);
        return body;
    }

    private JavaAst.Stmt parseStatement() {
        int line = peek().line();
        if (check(TokenKind.LBRACE)) {
            return new JavaAst.BlockStmt(List.copyOf(parseBlock()), line);
        }
        if (check(TokenKind.SEMI)) {
            advance();
            return new JavaAst.EmptyStmt(line);
        }
        if (check(TokenKind.AT)) {
            // statement-local annotation: skip, then reparse
            skipAnnotation();
            return parseStatement();
        }
        TokenKind k = peek().kind();
        switch (k) {
            case IF -> {
                advance();
                expect(TokenKind.LPAREN);
                JavaAst.Expr cond = parseExpression();
                expect(TokenKind.RPAREN);
                List<JavaAst.Stmt> thenBody = blockAsList(parseStatement());
                List<JavaAst.Stmt> elseBody = List.of();
                if (match(TokenKind.ELSE)) {
                    elseBody = blockAsList(parseStatement());
                }
                return new JavaAst.IfStmt(cond, thenBody, elseBody, line);
            }
            case WHILE -> {
                advance();
                expect(TokenKind.LPAREN);
                JavaAst.Expr cond = parseExpression();
                expect(TokenKind.RPAREN);
                return new JavaAst.WhileStmt(cond, List.copyOf(blockAsList(parseStatement())), line);
            }
            case DO -> {
                advance();
                List<JavaAst.Stmt> body = blockAsList(parseStatement());
                expect(TokenKind.WHILE);
                expect(TokenKind.LPAREN);
                JavaAst.Expr cond = parseExpression();
                expect(TokenKind.RPAREN);
                expect(TokenKind.SEMI);
                return new JavaAst.DoWhileStmt(cond, List.copyOf(body), line);
            }
            case FOR -> {
                return parseFor(line);
            }
            case RETURN -> {
                advance();
                JavaAst.Expr value = check(TokenKind.SEMI) ? null : parseExpression();
                expect(TokenKind.SEMI);
                return new JavaAst.ReturnStmt(value, line);
            }
            case THROW -> {
                advance();
                JavaAst.Expr value = parseExpression();
                expect(TokenKind.SEMI);
                return new JavaAst.ThrowStmt(value, line);
            }
            case BREAK -> {
                advance();
                String label = check(TokenKind.IDENT) ? advance().text() : null;
                expect(TokenKind.SEMI);
                return new JavaAst.BreakStmt(label, line);
            }
            case CONTINUE -> {
                advance();
                String label = check(TokenKind.IDENT) ? advance().text() : null;
                expect(TokenKind.SEMI);
                return new JavaAst.ContinueStmt(label, line);
            }
            case TRY -> {
                return parseTry(line);
            }
            case SWITCH -> {
                return parseSwitch(line);
            }
            case SYNCHRONIZED -> {
                advance();
                expect(TokenKind.LPAREN);
                JavaAst.Expr monitor = parseExpression();
                expect(TokenKind.RPAREN);
                return new JavaAst.SynchronizedStmt(monitor, List.copyOf(parseBlock()), line);
            }
            case ASSERT -> {
                advance();
                JavaAst.Expr condition = parseExpression();
                JavaAst.Expr detail = null;
                if (match(TokenKind.COLON)) {
                    detail = parseExpression();
                }
                expect(TokenKind.SEMI);
                return new JavaAst.AssertStmt(condition, detail, line);
            }
            case IDENT -> {
                if (isLabeledStatement()) {
                    String label = advance().text();
                    advance(); // colon
                    return new JavaAst.LabeledStmt(label, parseStatement(), line);
                }
                if (startsWithLocalVarDecl()) {
                    return parseLocalVarDecl(line);
                }
                JavaAst.Expr expr = parseExpression();
                expect(TokenKind.SEMI);
                return new JavaAst.ExpressionStmt(expr, line);
            }
            default -> {
                if (isTypeStart(k) && startsWithLocalVarDecl()) {
                    return parseLocalVarDecl(line);
                }
                JavaAst.Expr expr = parseExpression();
                expect(TokenKind.SEMI);
                return new JavaAst.ExpressionStmt(expr, line);
            }
        }
    }

    private List<JavaAst.Stmt> blockAsList(JavaAst.Stmt stmt) {
        return stmt instanceof JavaAst.BlockStmt b ? b.body() : List.of(stmt);
    }

    private boolean isLabeledStatement() {
        return check(TokenKind.IDENT) && tokens.get(pos + 1).kind() == TokenKind.COLON;
    }

    private static boolean isTypeStart(TokenKind k) {
        return k == TokenKind.VOID || k == TokenKind.BOOLEAN || k == TokenKind.INT || k == TokenKind.LONG
                || k == TokenKind.SHORT || k == TokenKind.BYTE || k == TokenKind.CHAR
                || k == TokenKind.FLOAT || k == TokenKind.DOUBLE;
    }

    private boolean startsWithLocalVarDecl() {
        int save = pos;
        try {
            parseModifiers();
            if (isContextualVar()) {
                return true;
            }
            if (isTypeStart(peek().kind())) {
                advance();
                skipTypeArguments();
                return check(TokenKind.IDENT);
            }
            if (peek().kind() != TokenKind.IDENT) {
                return false;
            }
            readTypeName();
            // after a type must come the declarator name; a '.' means it was an expression
            if (peek().kind() != TokenKind.IDENT) {
                return false;
            }
            // enhanced-for / ordinary declaration distinction handled by caller
            return true;
        } catch (RuntimeException e) {
            return false;
        } finally {
            pos = save;
        }
    }

    private JavaAst.Stmt parseLocalVarDecl(int line) {
        parseModifiers();
        String type;
        if (isContextualVar()) {
            advance();
            type = "var";
        } else {
            type = readTypeName();
        }
        List<JavaAst.VarDecl> declarators = new ArrayList<>();
        declarators.add(parseOneVarDecl(type));
        while (match(TokenKind.COMMA)) {
            declarators.add(parseOneVarDecl(type));
        }
        expect(TokenKind.SEMI);
        return new JavaAst.LocalVarStmt(List.copyOf(declarators), line);
    }

    private boolean isContextualVar() {
        return check(TokenKind.IDENT) && "var".equals(peek().text());
    }

    private JavaAst.VarDecl parseOneVarDecl(String type) {
        String name = expect(TokenKind.IDENT).text();
        int line = peek().line();
        while (check(TokenKind.LBRACKET)) {
            advance();
            expect(TokenKind.RBRACKET);
        }
        JavaAst.Expr init = null;
        if (match(TokenKind.ASSIGN)) {
            init = check(TokenKind.LBRACE)
                    ? new JavaAst.ArrayInitExpr(parseArrayInitializerElements(), line)
                    : parseExpression();
        }
        return new JavaAst.VarDecl(name, type, init, line);
    }

    private JavaAst.Stmt parseFor(int line) {
        advance();
        expect(TokenKind.LPAREN);
        if (startsWithEnhancedForDecl()) {
            parseModifiers();
            String varType = isContextualVar() ? (advance().text()) : readTypeName();
            String varName = expect(TokenKind.IDENT).text();
            expect(TokenKind.COLON);
            JavaAst.Expr iterable = parseExpression();
            expect(TokenKind.RPAREN);
            List<JavaAst.Stmt> body = blockAsList(parseStatement());
            return new JavaAst.EnhancedForStmt(varName, varType, iterable, List.copyOf(body), line);
        }
        List<JavaAst.Stmt> init = new ArrayList<>();
        if (!check(TokenKind.SEMI)) {
            if (startsWithLocalVarDecl()) {
                init.add(parseLocalVarDeclNoSemi());
                expect(TokenKind.SEMI);
            } else {
                JavaAst.Expr expr = parseExpression();
                expect(TokenKind.SEMI);
                init.add(new JavaAst.ExpressionStmt(expr, line));
            }
        } else {
            advance();
        }
        JavaAst.Expr cond = check(TokenKind.SEMI) ? null : parseExpression();
        expect(TokenKind.SEMI);
        List<JavaAst.Expr> update = new ArrayList<>();
        if (!check(TokenKind.RPAREN)) {
            update.add(parseExpression());
            while (match(TokenKind.COMMA)) {
                update.add(parseExpression());
            }
        }
        expect(TokenKind.RPAREN);
        List<JavaAst.Stmt> body = blockAsList(parseStatement());
        return new JavaAst.ForStmt(List.copyOf(init), cond, List.copyOf(update), List.copyOf(body), line);
    }

    private boolean startsWithEnhancedForDecl() {
        int save = pos;
        try {
            parseModifiers();
            if (isContextualVar()) {
                advance();
            } else {
                if (!isTypeStart(peek().kind()) && peek().kind() != TokenKind.IDENT) {
                    return false;
                }
                readTypeName();
            }
            if (peek().kind() != TokenKind.IDENT) {
                return false;
            }
            advance();
            return check(TokenKind.COLON);
        } catch (RuntimeException e) {
            return false;
        } finally {
            pos = save;
        }
    }

    private JavaAst.Stmt parseLocalVarDeclNoSemi() {
        int line = peek().line();
        parseModifiers();
        String type = isContextualVar() ? (advance().text()) : readTypeName();
        List<JavaAst.VarDecl> declarators = new ArrayList<>();
        declarators.add(parseOneVarDecl(type));
        while (match(TokenKind.COMMA)) {
            declarators.add(parseOneVarDecl(type));
        }
        return new JavaAst.LocalVarStmt(List.copyOf(declarators), line);
    }

    private JavaAst.Stmt parseTry(int line) {
        advance();
        List<JavaAst.Stmt> resources = new ArrayList<>();
        if (match(TokenKind.LPAREN)) {
            while (!check(TokenKind.RPAREN)) {
                if (startsWithLocalVarDecl()) {
                    resources.add(parseLocalVarDeclNoSemi());
                } else {
                    JavaAst.Expr e = parseExpression();
                    resources.add(new JavaAst.ExpressionStmt(e, line));
                }
                match(TokenKind.SEMI);
            }
            expect(TokenKind.RPAREN);
        }
        List<JavaAst.Stmt> body = parseBlock();
        List<JavaAst.CatchClause> catches = new ArrayList<>();
        while (match(TokenKind.CATCH)) {
            expect(TokenKind.LPAREN);
            parseModifiers();
            String type = readTypeName();
            // multi-catch: A | B
            while (check(TokenKind.PIPE)) {
                advance();
                readTypeName();
            }
            String paramName = expect(TokenKind.IDENT).text();
            expect(TokenKind.RPAREN);
            List<JavaAst.Stmt> catchBody = parseBlock();
            catches.add(new JavaAst.CatchClause(paramName, type, List.copyOf(catchBody), line));
        }
        List<JavaAst.Stmt> finallyBody = List.of();
        if (match(TokenKind.FINALLY)) {
            finallyBody = List.copyOf(parseBlock());
        }
        return new JavaAst.TryStmt(List.copyOf(resources), List.copyOf(body),
                List.copyOf(catches), finallyBody, line);
    }

    private JavaAst.Stmt parseSwitch(int line) {
        advance();
        expect(TokenKind.LPAREN);
        JavaAst.Expr selector = parseExpression();
        expect(TokenKind.RPAREN);
        expect(TokenKind.LBRACE);
        List<JavaAst.SwitchCase> cases = new ArrayList<>();
        while (!check(TokenKind.RBRACE) && !atEnd()) {
            int caseLine = peek().line();
            List<JavaAst.Expr> labels = new ArrayList<>();
            boolean isDefault = false;
            if (match(TokenKind.CASE)) {
                if (check(TokenKind.DEFAULT)) {
                    advance();
                    isDefault = true;
                } else {
                    labels.add(parseExpression());
                    while (match(TokenKind.COMMA)) {
                        labels.add(parseExpression());
                    }
                }
                if (match(TokenKind.ARROW) || match(TokenKind.COLON)) {
                    // labels consumed
                }
            } else if (match(TokenKind.DEFAULT)) {
                isDefault = true;
                if (match(TokenKind.ARROW) || match(TokenKind.COLON)) {
                    // consumed
                }
            }
            List<JavaAst.Stmt> body = new ArrayList<>();
            while (!check(TokenKind.RBRACE) && !check(TokenKind.CASE)
                    && !check(TokenKind.DEFAULT)) {
                body.add(parseStatement());
            }
            cases.add(new JavaAst.SwitchCase(List.copyOf(labels), isDefault, List.copyOf(body), caseLine));
        }
        expect(TokenKind.RBRACE);
        return new JavaAst.SwitchStmt(selector, List.copyOf(cases), line);
    }

    private JavaAst.Expr parseExpression() {
        return parseAssignment();
    }

    private JavaAst.Expr parseAssignment() {
        JavaAst.Expr left = parseLambdaOrTernary();
        TokenKind k = peek().kind();
        if (k == TokenKind.ASSIGN || k == TokenKind.PLUS_ASSIGN || k == TokenKind.MINUS_ASSIGN
                || k == TokenKind.STAR_ASSIGN || k == TokenKind.SLASH_ASSIGN || k == TokenKind.PERCENT_ASSIGN
                || k == TokenKind.AMP_ASSIGN || k == TokenKind.PIPE_ASSIGN || k == TokenKind.CARET_ASSIGN
                || k == TokenKind.SHL_ASSIGN || k == TokenKind.SHR_ASSIGN || k == TokenKind.USHR_ASSIGN) {
            String op = advance().text();
            JavaAst.Expr right = parseAssignment();
            return new JavaAst.AssignExpr(op, left, right, left.line());
        }
        return left;
    }

    /** Either a lambda expression or the usual ternary/binary expression. */
    private JavaAst.Expr parseLambdaOrTernary() {
        int save = pos;
        int line = peek().line();
        JavaAst.LambdaExpr lambda = tryParseLambda(line);
        if (lambda != null) {
            return lambda;
        }
        pos = save;
        return parseTernary();
    }

    private JavaAst.LambdaExpr tryParseLambda(int line) {
        List<String> params = new ArrayList<>();
        if (check(TokenKind.IDENT) && tokens.get(pos + 1).kind() == TokenKind.ARROW) {
            params.add(advance().text());
            advance();
            return finishLambda(line, params);
        }
        if (check(TokenKind.LPAREN)) {
            int depth = 0;
            int cursor = pos;
            boolean paramsOnly = true;
            while (cursor < tokens.size()) {
                TokenKind k = tokens.get(cursor).kind();
                if (k == TokenKind.LPAREN) {
                    depth++;
                } else if (k == TokenKind.RPAREN) {
                    depth--;
                    if (depth == 0) {
                        break;
                    }
                } else if (k == TokenKind.ARROW && depth == 1) {
                    // arrow inside the first parens would be weird; ignore
                }
                cursor++;
            }
            if (cursor + 1 < tokens.size() && tokens.get(cursor + 1).kind() == TokenKind.ARROW) {
                advance(); // (
                while (!check(TokenKind.RPAREN)) {
                    parseModifiers();
                    if (isTypeStart(peek().kind()) || peek().kind() == TokenKind.IDENT) {
                        // could be typed param or single param name; read type if followed by IDENT IDENT
                        int s2 = pos;
                        if (peek().kind() == TokenKind.IDENT && tokens.get(pos + 1).kind() == TokenKind.IDENT) {
                            readTypeName();
                        } else if (isTypeStart(peek().kind())) {
                            readTypeName();
                        }
                        if (check(TokenKind.IDENT)) {
                            params.add(advance().text());
                        } else {
                            pos = s2;
                            break;
                        }
                    }
                    if (!match(TokenKind.COMMA)) {
                        break;
                    }
                }
                expect(TokenKind.RPAREN);
                expect(TokenKind.ARROW);
                return finishLambda(line, params);
            }
        }
        return null;
    }

    private JavaAst.LambdaExpr finishLambda(int line, List<String> params) {
        if (check(TokenKind.LBRACE)) {
            return new JavaAst.LambdaExpr(List.copyOf(params), List.copyOf(parseBlock()), null, line);
        }
        JavaAst.Expr body = parseAssignment();
        return new JavaAst.LambdaExpr(List.copyOf(params), List.of(), body, line);
    }

    private JavaAst.Expr parseTernary() {
        JavaAst.Expr cond = parseBinary(0);
        if (match(TokenKind.QUESTION)) {
            JavaAst.Expr thenValue = parseAssignment();
            expect(TokenKind.COLON);
            JavaAst.Expr elseValue = parseAssignment();
            return new JavaAst.ConditionalExpr(cond, thenValue, elseValue, cond.line());
        }
        return cond;
    }

    private static final String[][] BINARY_PRECEDENCE = {
            {"||"},
            {"&&"},
            {"|"},
            {"^"},
            {"&"},
            {"==", "!="},
            {"<", ">", "<=", ">=", "instanceof"},
            {"<<", ">>", ">>>"},
            {"+", "-"},
            {"*", "/", "%"}
    };

    private JavaAst.Expr parseBinary(int level) {
        if (level >= BINARY_PRECEDENCE.length) {
            return parseUnary();
        }
        JavaAst.Expr left = parseBinary(level + 1);
        while (true) {
            Token t = peek();
            String op = null;
            if (t.kind() == TokenKind.INSTANCEOF && containsOp(BINARY_PRECEDENCE[level], "instanceof")) {
                op = "instanceof";
            } else {
                for (String candidate : BINARY_PRECEDENCE[level]) {
                    if (!"instanceof".equals(candidate) && t.text().equals(candidate)) {
                        op = candidate;
                        break;
                    }
                }
            }
            if (op == null) {
                break;
            }
            int opLine = t.line();
            advance();
            if ("instanceof".equals(op)) {
                String typeName = readTypeName();
                String binding = null;
                if (check(TokenKind.IDENT) && !isFollowingExpressionContinuation()) {
                    binding = advance().text();
                }
                left = new JavaAst.InstanceOfExpr(left, typeName, binding, opLine);
                continue;
            }
            JavaAst.Expr right = parseBinary(level + 1);
            left = new JavaAst.BinaryExpr(op, left, right, opLine);
        }
        return left;
    }

    private static boolean containsOp(String[] ops, String op) {
        for (String o : ops) {
            if (o.equals(op)) {
                return true;
            }
        }
        return false;
    }

    private boolean isFollowingExpressionContinuation() {
        return check(TokenKind.DOT) || check(TokenKind.LPAREN);
    }

    private JavaAst.Expr parseUnary() {
        Token t = peek();
        TokenKind k = t.kind();
        if (k == TokenKind.PLUS || k == TokenKind.MINUS || k == TokenKind.BANG || k == TokenKind.TILDE
                || k == TokenKind.INC || k == TokenKind.DEC) {
            advance();
            return new JavaAst.UnaryExpr(t.text(), parseUnary(), true, t.line());
        }
        JavaAst.Expr expr = parsePrimary();
        while (check(TokenKind.INC) || check(TokenKind.DEC)) {
            Token op = advance();
            expr = new JavaAst.UnaryExpr(op.text(), expr, false, op.line());
        }
        return expr;
    }

    private JavaAst.Expr parsePrimary() {
        Token t = peek();
        JavaAst.Expr expr;
        switch (t.kind()) {
            case INT_LITERAL, FLOAT_LITERAL, CHAR_LITERAL, STRING_LITERAL, TEXT_BLOCK -> {
                advance();
                expr = new JavaAst.LiteralExpr(t.text(),
                        t.kind() == TokenKind.STRING_LITERAL || t.kind() == TokenKind.TEXT_BLOCK
                                ? "string" : t.kind() == TokenKind.CHAR_LITERAL ? "char"
                                : t.kind() == TokenKind.FLOAT_LITERAL ? "float" : "int", t.line());
            }
            case TRUE, FALSE -> {
                advance();
                expr = new JavaAst.LiteralExpr(t.text(), "boolean", t.line());
            }
            case NULL -> {
                advance();
                expr = new JavaAst.LiteralExpr(t.text(), "null", t.line());
            }
            case THIS -> {
                advance();
                String qualifier = null;
                expr = new JavaAst.ThisExpr(qualifier, t.line());
            }
            case SUPER -> {
                advance();
                expr = new JavaAst.SuperExpr(null, t.line());
            }
            case LPAREN -> {
                // cast: (Type) x  or parenthesized expr
                int save = pos;
                advance();
                if (looksLikeCast()) {
                    String typeName = readTypeName();
                    expect(TokenKind.RPAREN);
                    expr = new JavaAst.CastExpr(typeName, parseUnary(), t.line());
                } else {
                    JavaAst.Expr inner = parseExpression();
                    expect(TokenKind.RPAREN);
                    expr = new JavaAst.ParenExpr(inner, t.line());
                }
            }
            case NEW -> expr = parseNew();
            case SWITCH -> expr = parseSwitchExpression();
            default -> {
                if (t.kind() == TokenKind.IDENT || isTypeStart(t.kind())) {
                    expr = new JavaAst.IdentExpr(t.text(), t.line());
                    advance();
                } else {
                    throw syntax("unexpected token in expression: '" + t.text() + "'");
                }
            }
        }
        return parsePostfix(expr);
    }

    private boolean looksLikeCast() {
        int save = pos;
        try {
            parseModifiers();
            if (!isTypeStart(peek().kind()) && peek().kind() != TokenKind.IDENT) {
                return false;
            }
            readTypeName();
            boolean cast = check(TokenKind.RPAREN);
            return cast;
        } catch (RuntimeException e) {
            return false;
        } finally {
            pos = save;
        }
    }

    /**
     * Parses a switch expression into a conservative ternary-like value tree:
     * the selector and every case value contribute their data dependencies.
     * {@code yield} inside block branches is treated as an expression statement.
     */
    private JavaAst.Expr parseSwitchExpression() {
        Token keyword = expect(TokenKind.SWITCH);
        expect(TokenKind.LPAREN);
        JavaAst.Expr selector = parseExpression();
        expect(TokenKind.RPAREN);
        expect(TokenKind.LBRACE);
        JavaAst.Expr combined = null;
        List<JavaAst.Expr> labelValues = new ArrayList<>();
        while (!check(TokenKind.RBRACE) && !atEnd()) {
            boolean isDefault = false;
            List<JavaAst.Expr> labels = new ArrayList<>();
            if (match(TokenKind.CASE)) {
                if (check(TokenKind.DEFAULT)) {
                    advance();
                    isDefault = true;
                } else {
                    labels.add(parseExpression());
                    while (match(TokenKind.COMMA)) {
                        labels.add(parseExpression());
                    }
                }
            } else if (match(TokenKind.DEFAULT)) {
                isDefault = true;
            }
            expectOneOfArrowOrColon();
            if (check(TokenKind.LBRACE)) {
                List<JavaAst.Stmt> block = parseBlock();
                for (JavaAst.Stmt s : block) {
                    if (s instanceof JavaAst.ExpressionStmt es) {
                        labelValues.add(es.expr());
                    }
                }
            } else {
                labelValues.add(parseExpression());
                match(TokenKind.SEMI);
            }
            match(TokenKind.CASE);
            match(TokenKind.DEFAULT);
        }
        expect(TokenKind.RBRACE);
        combined = selector;
        for (JavaAst.Expr v : labelValues) {
            combined = new JavaAst.BinaryExpr("+", combined, v, keyword.line());
        }
        return combined;
    }

    private void expectOneOfArrowOrColon() {
        if (!match(TokenKind.ARROW) && !match(TokenKind.COLON)) {
            throw syntax("expected '->' or ':' in switch");
        }
    }

    private JavaAst.Expr parseNew() {
        Token newTok = expect(TokenKind.NEW);
        int line = newTok.line();
        JavaAst.Expr enclosing = null;
        if (check(TokenKind.IDENT) && tokens.get(pos + 1).kind() == TokenKind.DOT) {
            enclosing = new JavaAst.IdentExpr(advance().text(), line);
            expect(TokenKind.DOT);
            expect(TokenKind.NEW);
        }
        // new int[n][m]{...} or new Foo(args)
        StringBuilder typeName = new StringBuilder(readTypeHead());
        skipTypeArguments();
        List<JavaAst.Expr> dimensions = new ArrayList<>();
        boolean hasArray = false;
        while (check(TokenKind.LBRACKET)) {
            hasArray = true;
            advance();
            if (!check(TokenKind.RBRACKET)) {
                dimensions.add(parseExpression());
            }
            expect(TokenKind.RBRACKET);
            typeName.append("[]");
        }
        if (hasArray) {
            List<JavaAst.Expr> init = List.of();
            if (check(TokenKind.LBRACE)) {
                init = parseArrayInitializerElements();
            }
            return new JavaAst.NewArrayExpr(typeName.toString(), List.copyOf(dimensions), init, line);
        }
        List<JavaAst.Expr> args = parseArguments();
        JavaAst.TypeDecl anonymousBody = null;
        if (check(TokenKind.LBRACE)) {
            // anonymous class body: parse members via a type decl wrapper
            anonymousBody = parseAnonymousBody(typeName.toString(), line);
        }
        return new JavaAst.NewExpr(typeName.toString(), List.copyOf(args), enclosing, anonymousBody, line);
    }

    private JavaAst.TypeDecl parseAnonymousBody(String superName, int line) {
        expect(TokenKind.LBRACE);
        List<JavaAst.Member> members = parseMembers("", "");
        expect(TokenKind.RBRACE);
        return new JavaAst.TypeDecl("", "anonymous", "", List.of(superName), List.of(),
                List.of(), List.copyOf(members), List.of(), false, file, line);
    }

    private List<JavaAst.Expr> parseArguments() {
        expect(TokenKind.LPAREN);
        List<JavaAst.Expr> args = new ArrayList<>();
        if (!check(TokenKind.RPAREN)) {
            args.add(parseExpression());
            while (match(TokenKind.COMMA)) {
                args.add(parseExpression());
            }
        }
        expect(TokenKind.RPAREN);
        return args;
    }

    private List<JavaAst.Expr> parseArrayInitializerElements() {
        expect(TokenKind.LBRACE);
        List<JavaAst.Expr> elements = new ArrayList<>();
        while (!check(TokenKind.RBRACE)) {
            if (check(TokenKind.LBRACE)) {
                elements.add(new JavaAst.ArrayInitExpr(parseArrayInitializerElements(), peek().line()));
            } else {
                elements.add(parseAssignment());
            }
            if (!match(TokenKind.COMMA)) {
                break;
            }
        }
        expect(TokenKind.RBRACE);
        return List.copyOf(elements);
    }

    private JavaAst.Expr parsePostfix(JavaAst.Expr expr) {
        while (true) {
            if (check(TokenKind.DOT)) {
                Token dot = advance();
                if (check(TokenKind.NEW)) {
                    // qualifier.new Inner(args) — represented as NewExpr via generic path
                    // (rare for taint; degrade to a call named "<new>" on qualifier)
                    advance();
                    String typeName = readTypeHead();
                    skipTypeArguments();
                    List<JavaAst.Expr> args = parseArguments();
                    expr = new JavaAst.NewExpr(typeName, List.copyOf(args), expr, null, dot.line());
                    continue;
                }
                if (check(TokenKind.COLONCOLON)) {
                    advance();
                    String name;
                    boolean isNewRef = check(TokenKind.NEW);
                    if (isNewRef) {
                        advance();
                        name = "new";
                    } else {
                        name = expect(TokenKind.IDENT).text();
                    }
                    expr = new JavaAst.MethodRefExpr(expr, name, isNewRef, dot.line());
                    continue;
                }
                Token nameTok;
                if (check(TokenKind.IDENT) || check(TokenKind.CLASS)) {
                    nameTok = advance();
                } else if (isTypeStart(peek().kind())) {
                    nameTok = advance();
                } else {
                    throw syntax("expected identifier after '.'");
                }
                if (check(TokenKind.LPAREN)) {
                    List<JavaAst.Expr> args = parseArguments();
                    expr = new JavaAst.CallExpr(expr, nameTok.text(), List.copyOf(args), dot.line());
                } else {
                    expr = new JavaAst.FieldAccessExpr(expr, nameTok.text(), dot.line());
                }
            } else if (check(TokenKind.LBRACKET)) {
                Token bracket = advance();
                JavaAst.Expr index = parseExpression();
                expect(TokenKind.RBRACKET);
                expr = new JavaAst.ArrayAccessExpr(expr, index, bracket.line());
            } else if (check(TokenKind.LPAREN)) {
                // direct call with null target handled at Ident level; a bare expr in parens
                // cannot be called in Java, but tolerate: f(...) parsed when expr is Ident
                List<JavaAst.Expr> args = parseArguments();
                if (expr instanceof JavaAst.IdentExpr id) {
                    expr = new JavaAst.CallExpr(null, id.name(), List.copyOf(args), id.line());
                } else if (expr instanceof JavaAst.ThisExpr) {
                    expr = new JavaAst.CallExpr(expr, "<init>", List.copyOf(args), expr.line());
                } else if (expr instanceof JavaAst.SuperExpr) {
                    expr = new JavaAst.CallExpr(expr, "<superinit>", List.copyOf(args), expr.line());
                } else {
                    expr = new JavaAst.CallExpr(expr, "invoke", List.copyOf(args), expr.line());
                }
            } else if (check(TokenKind.COLONCOLON)) {
                Token cc = advance();
                String name;
                boolean isNew = check(TokenKind.NEW);
                if (isNew) {
                    advance();
                    name = "new";
                } else {
                    name = expect(TokenKind.IDENT).text();
                }
                expr = new JavaAst.MethodRefExpr(expr, name, isNew, cc.line());
            } else {
                break;
            }
        }
        return expr;
    }

    private Token peek() {
        return tokens.get(pos);
    }

    private boolean check(TokenKind kind) {
        return peek().kind() == kind;
    }

    private boolean atEnd() {
        return peek().kind() == TokenKind.EOF;
    }

    private Token advance() {
        return tokens.get(pos++);
    }

    private boolean match(TokenKind kind) {
        if (check(kind)) {
            advance();
            return true;
        }
        return false;
    }

    private Token expect(TokenKind kind) {
        if (!check(kind)) {
            throw syntax("expected " + kind + " but found '" + peek().text() + "'");
        }
        return advance();
    }

    private JavaParseException syntax(String message) {
        return new JavaParseException(file, peek().line(), JavaParseException.Reason.SYNTAX, message);
    }

    private JavaParseException unsupported(String message) {
        return new JavaParseException(file, peek().line(), JavaParseException.Reason.UNSUPPORTED, message);
    }
}
