package com.github.guoyyit.statictaintanalyzerjava.lang.java;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JavaParserSmokeTest {

    private final JavaParser parser = new JavaParser();

    @Test
    void parsesPackageImportsClassMethodsAndControlFlow() {
        String src = """
                package com.acme.web;

                import java.util.List;
                import com.acme.db.Dao;

                public class UserService extends BaseService implements Service, AutoCloseable {
                    private static final Dao DAO = new Dao();
                    private String prefix;

                    public UserService(String prefix) {
                        this.prefix = prefix;
                    }

                    public String handle(String name, int count) {
                        String q = "select " + name;
                        for (int i = 0; i < count; i++) {
                            q = q + name;
                        }
                        if (count > 0) {
                            return DAO.query(q);
                        } else {
                            return null;
                        }
                    }

                    private static long staticMethod(List<String> xs) {
                        long acc = 0;
                        for (String x : xs) {
                            acc += x.length();
                        }
                        return acc;
                    }

                    @Override
                    public void close() {
                    }
                }
                """;
        JavaAst.CompilationUnit unit = parser.parse("UserService.java", src);
        assertEquals("com.acme.web", unit.packageName());
        assertEquals(2, unit.imports().size());
        assertEquals(1, unit.types().size());
        JavaAst.TypeDecl type = unit.types().get(0);
        assertEquals("UserService", type.name());
        assertEquals("com.acme.web.UserService", type.qualifiedName());
        assertEquals("BaseService", type.extendsNames().get(0));
        assertEquals(2, type.implementsNames().size());
        assertEquals(6, type.members().size());
        JavaAst.MethodDecl ctor = (JavaAst.MethodDecl) type.members().get(2);
        assertTrue(ctor.isConstructor());
        JavaAst.MethodDecl handle = (JavaAst.MethodDecl) type.members().get(3);
        assertEquals("handle", handle.name());
        assertFalse(handle.isStatic());
        assertEquals(2, handle.params().size());
        assertTrue(handle.body().get(1) instanceof JavaAst.ForStmt);
        assertTrue(handle.body().get(2) instanceof JavaAst.IfStmt);
        JavaAst.MethodDecl staticMethod = (JavaAst.MethodDecl) type.members().get(4);
        assertTrue(staticMethod.isStatic());
        assertTrue(staticMethod.body().get(1) instanceof JavaAst.EnhancedForStmt);
    }

    @Test
    void parseErrorCarriesFileLineAndReason() {
        JavaParseException e = assertThrows(JavaParseException.class,
                () -> parser.parse("Broken.java", "class Broken { void m() { if ( } }"));
        assertEquals("Broken.java", e.file());
        assertTrue(e.line() >= 1);
        assertEquals(JavaParseException.Reason.SYNTAX, e.reason());
    }

    @Test
    void lexicalErrorIsDistinctFromSyntax() {
        JavaParseException e = assertThrows(JavaParseException.class,
                () -> parser.parse("Bad.java", "class Bad { String s = \"unterminated; }"));
        assertEquals(JavaParseException.Reason.LEXICAL, e.reason());
    }
}
