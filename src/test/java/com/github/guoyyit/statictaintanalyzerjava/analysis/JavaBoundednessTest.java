package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

class JavaBoundednessTest {

    private static final String RULES = """
            {
              "sources": [{"id":"s","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"k","pattern":"*.execute","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    @Test
    void largeRecursiveAndLoopingProjectFinishesBounded() {
        Map<String, String> files = new TreeMap<>();
        StringBuilder methods = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            methods.append("""
                    public String m%d(String x) {
                        while (x != null) {
                            for (int j = 0; j < 10; j++) {
                                x = m%d(x) + x;
                            }
                        }
                        return x;
                    }
                    """.formatted(i, (i + 1) % 200));
        }
        files.put("Big.java", """
                package big;
                public class Big {
                    public String readParam(String k) { return k; }
                    public void execute(String q) { }
                    %s
                    public void entry() {
                        String v = readParam("v");
                        execute(m0(v));
                    }
                }
                """.formatted(methods));

        long start = System.currentTimeMillis();
        AnalysisResult result = new AnalysisEngine().analyze(files,
                AnalysisRules.fromJson(RULES), null);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(result.parseFailures().isEmpty(), "large valid file parses");
        assertFalse(result.findings().isEmpty(), "bounded recursion still finds the flow");
        assertTrue(result.findings().stream()
                        .allMatch(f -> f.path().size() <= TaintEngine.MAX_PATH_LENGTH),
                "paths stay within the step bound");
        assertTrue(elapsed < 20_000, "analysis of a large file stays bounded, took " + elapsed + "ms");
    }

    @Test
    void manyFilesAcrossPackagesCompleteInBoundedTime() {
        Map<String, String> files = new TreeMap<>();
        for (int i = 0; i < 120; i++) {
            String pkg = "pkg" + (i % 8);
            files.put("src/" + pkg + "/Cls" + i + ".java", """
                    package %s;
                    public class Cls%d {
                        public String readParam(String k) { return k; }
                        public void execute(String q) { }
                        public void run() { execute(readParam("p")); }
                    }
                    """.formatted(pkg, i));
        }
        long start = System.currentTimeMillis();
        AnalysisResult result = new AnalysisEngine().analyze(files,
                AnalysisRules.fromJson(RULES), null);
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(result.parseFailures().isEmpty());
        assertEquals(120, result.findings().size());
        assertTrue(elapsed < 20_000, "120 files analyzed in bounded time, took " + elapsed + "ms");
    }

    @Test
    void unsupportedOrBrokenConstructFailsIsolatedWithReason() {
        Map<String, String> files = new TreeMap<>();
        files.put("good/G.java", """
                package demo;
                public class G {
                    public String readParam(String k) { return k; }
                    public void execute(String q) { }
                    public void m() { execute(readParam("x")); }
                }
                """);
        files.put("broken/Lex.java", "package demo; public class Lex { String s = \"unterminated; }");
        files.put("broken/Syn.java", "package demo; public class Syn { void m(){ if( } }");
        AnalysisResult result = new AnalysisEngine().analyze(files,
                AnalysisRules.fromJson(RULES), null);
        assertEquals(2, result.parseFailures().size());
        assertEquals(1, result.findings().size(), "good file unaffected by broken ones");
        boolean hasLexical = result.parseFailures().stream()
                .anyMatch(f -> f.reason().equals(ParseFailure.LEXICAL));
        boolean hasSyntax = result.parseFailures().stream()
                .anyMatch(f -> f.reason().equals(ParseFailure.SYNTAX));
        assertTrue(hasLexical && hasSyntax, "distinct failure reasons are preserved");
        assertTrue(result.parseFailures().stream().allMatch(f -> f.line() >= 1 && !f.file().isBlank()));
    }
}
