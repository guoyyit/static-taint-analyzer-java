package com.github.guoyyit.statictaintanalyzerjava.lang;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ParserTest {

    private final Parser parser = new Parser();

    @Test
    void parsesFunctionsStatementsAndExpressions() {
        Ast.Program program = parser.parse("t.req", """
                // a comment
                fn f(a, b) {
                  x = g(a) + "lit";
                  if (x) {
                    y = 1;
                  } else {
                    y = 2;
                  }
                  while (y) {
                    h(y);
                  }
                  return x;
                }
                """);
        assertEquals(1, program.functions().size());
        Ast.FunctionDef fn = program.functions().get(0);
        assertEquals("f", fn.name());
        assertEquals(java.util.List.of("a", "b"), fn.params());
        assertEquals(4, fn.body().size());
        assertInstanceOf(Ast.Assign.class, fn.body().get(0));
        assertInstanceOf(Ast.If.class, fn.body().get(1));
        assertInstanceOf(Ast.While.class, fn.body().get(2));
        assertInstanceOf(Ast.Return.class, fn.body().get(3));
        Ast.If ifStmt = (Ast.If) fn.body().get(1);
        assertEquals(1, ifStmt.thenBody().size());
        assertEquals(1, ifStmt.elseBody().size());
    }

    @Test
    void rejectsInvalidSource() {
        assertThrows(Lexer.ParseException.class, () -> parser.parse("t.req", "fn f( { }"));
        assertThrows(Lexer.ParseException.class, () -> parser.parse("t.req", "fn f() { x = ; }"));
    }
}
