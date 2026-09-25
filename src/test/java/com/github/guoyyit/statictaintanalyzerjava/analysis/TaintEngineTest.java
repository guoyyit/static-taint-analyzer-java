package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.domain.RuleSet;
import com.github.guoyyit.statictaintanalyzerjava.domain.TaintRule;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaintEngineTest {

    private static RuleSet rules() {
        return new RuleSet("1",
                List.of(TaintRule.of("http-param", "javax.servlet.http.HttpServletRequest.getParameter", "HIGH", "")),
                List.of(TaintRule.of("sql-exec", "java.sql.Statement.executeQuery", "HIGH", "SQL injection")),
                List.of(TaintRule.of("sql-escape", "demo.Sanitizer.escape", "LOW", "")));
    }

    private static TaintEngine engine(Map<String, String> sources) {
        return new TaintEngine(new JavaModelBuilder().buildFromStrings(sources), rules());
    }

    @Test
    void propagatesTaintAcrossFunctionsAndFiles() {
        Map<String, String> src = new TreeMap<>();
        src.put("demo/UserController.java", """
                package demo;
                public class UserController {
                    public String readName(javax.servlet.http.HttpServletRequest req) {
                        String name = req.getParameter("name");
                        return name;
                    }
                }
                """);
        src.put("demo/UserDao.java", """
                package demo;
                public class UserDao {
                    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                        UserController c = new UserController();
                        String n = c.readName(req);
                        String q = "select * from u where name='" + n + "'";
                        stmt.executeQuery(q);
                    }
                }
                """);
        TaintEngine.Result result = engine(src).analyzeAll(1);
        assertEquals(1, result.findings().size(), "expected exactly one cross-file finding");
        Finding f = result.findings().get(0);
        assertEquals("sql-exec", f.sinkRuleId());
        assertEquals("http-param", f.sourceRuleId());
        assertTrue(f.path().size() >= 3, "path should record propagation hops");
        assertFalse(f.fingerprint().isEmpty());
    }

    @Test
    void sanitizerKillsTaint() {
        Map<String, String> src = new TreeMap<>();
        src.put("demo/Sanitizer.java", """
                package demo;
                public class Sanitizer {
                    public static String escape(String s) { return s; }
                }
                """);
        src.put("demo/Dao.java", """
                package demo;
                public class Dao {
                    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                        String n = req.getParameter("name");
                        String safe = Sanitizer.escape(n);
                        stmt.executeQuery(safe);
                    }
                }
                """);
        TaintEngine.Result result = engine(src).analyzeAll(1);
        assertTrue(result.findings().isEmpty(), "sanitized value must not alert");
    }

    @Test
    void sanitizerOnOtherVariableDoesNotCleanTaintedOne() {
        Map<String, String> src = new TreeMap<>();
        src.put("demo/Sanitizer.java", """
                package demo;
                public class Sanitizer {
                    public static String escape(String s) { return s; }
                }
                """);
        src.put("demo/Dao.java", """
                package demo;
                public class Dao {
                    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                        String tainted = req.getParameter("name");
                        String other = Sanitizer.escape("constant");
                        stmt.executeQuery(tainted + other);
                    }
                }
                """);
        TaintEngine.Result result = engine(src).analyzeAll(1);
        assertEquals(1, result.findings().size(), "sanitizer bypass: tainted var still alerts");
    }

    @Test
    void recursionAndLoopsTerminateWithDeterministicResult() {
        Map<String, String> src = new TreeMap<>();
        src.put("demo/Rec.java", """
                package demo;
                public class Rec {
                    public String loop(javax.servlet.http.HttpServletRequest req) {
                        String acc = "";
                        for (int i = 0; i < 10; i++) {
                            acc = acc + req.getParameter("p");
                        }
                        return acc;
                    }
                    public String rec(int n, javax.servlet.http.HttpServletRequest req) {
                        if (n <= 0) {
                            return req.getParameter("x");
                        }
                        return rec(n - 1, req);
                    }
                    public void sink(java.sql.Statement stmt, javax.servlet.http.HttpServletRequest req) {
                        stmt.executeQuery(loop(req));
                        stmt.executeQuery(rec(3, req));
                    }
                }
                """);
        TaintEngine.Result first = engine(src).analyzeAll(1);
        TaintEngine.Result second = engine(src).analyzeAll(1);
        assertFalse(first.findings().isEmpty());
        assertEquals(first.findings(), second.findings(), "same input must reproduce identical findings");
    }

    @Test
    void aliasesPropagateTaint() {
        Map<String, String> src = new TreeMap<>();
        src.put("demo/Alias.java", """
                package demo;
                public class Alias {
                    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                        String a = req.getParameter("x");
                        String b = a;
                        StringBuilder sb = new StringBuilder();
                        sb.append(b);
                        stmt.executeQuery(sb.toString());
                    }
                }
                """);
        TaintEngine.Result result = engine(src).analyzeAll(1);
        assertEquals(1, result.findings().size(), "alias chain must propagate taint");
    }
}
