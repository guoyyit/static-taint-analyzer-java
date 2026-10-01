package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaAst;
import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaParser;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JavaTaintEngineTest {

    private static final String RULES = """
            {
              "sources": [
                {"id":"req-param","pattern":"com.acme.web.WebRequest#getParam","severity":"HIGH"},
                {"id":"req-bare","pattern":"readParam","severity":"HIGH"}
              ],
              "sinks": [
                {"id":"sql","pattern":"com.acme.db.Dao#execute","severity":"CRITICAL"},
                {"id":"log","pattern":"*.log","severity":"MEDIUM"}
              ],
              "sanitizers": [{"id":"escape","pattern":"*.escapeSql"}]
            }
            """;

    private final JavaParser parser = new JavaParser();
    private final JavaSummarizer summarizer = new JavaSummarizer();

    private AnalysisResult run(Map<String, String> files) {
        AnalysisRules rules = AnalysisRules.fromJson(RULES);
        return new AnalysisEngine().analyze(files, rules, null);
    }

    @Test
    void propagatesAcrossMethodsClassesAndPackages() {
        Map<String, String> files = Map.of(
                "com/acme/web/Controller.java", """
                        package com.acme.web;

                        import com.acme.db.Dao;
                        import com.acme.web.WebRequest;

                        public class Controller {
                            private Dao dao = new Dao();

                            public void get(WebRequest req) {
                                String name = req.getParam("name");
                                String query = build(name);
                                dao.execute(query);
                            }

                            private String build(String n) {
                                return "SELECT * FROM u WHERE n='" + n + "'";
                            }
                        }
                        """,
                "com/acme/db/Dao.java", """
                        package com.acme.db;

                        public class Dao {
                            public void execute(String sql) {
                            }
                        }
                        """,
                "com/acme/web/WebRequest.java", """
                        package com.acme.web;

                        public class WebRequest {
                            public String getParam(String key) {
                                return key;
                            }
                        }
                        """);
        AnalysisResult result = run(files);
        assertTrue(result.parseFailures().isEmpty(), "no parse failures: " + result.parseFailures());
        assertEquals(1, result.findings().size(), () -> "one finding, got " + result.findings());
        Finding f = result.findings().get(0);
        assertEquals("req-param", f.sourceRuleId());
        assertEquals("sql", f.sinkRuleId());
        List<String> classes = f.path().stream().map(Finding.Step::className).distinct().toList();
        assertTrue(classes.contains("com.acme.web.Controller"));
        assertTrue(classes.contains("com.acme.db.Dao"));
        for (Finding.Step step : f.path()) {
            assertFalse(step.file().isBlank());
            assertTrue(step.line() > 0);
            assertFalse(step.className().isBlank());
        }
    }

    @Test
    void fieldAliasesAndObjectConstructionAreTracked() {
        Map<String, String> files = Map.of(
                "a/com/app/Order.java", """
                        package com.app;

                        public class Order {
                            public String raw;
                        }
                        """,
                "a/com/app/Handler.java", """
                        package com.app;

                        public class Handler {
                            public String readParam(String k) { return k; }
                            public void log(String m) { }

                            public void handle() {
                                Order o = new Order();
                                String v = readParam("v");
                                o.raw = v;
                                Order alias = o;
                                log(alias.raw);
                            }
                        }
                        """);
        AnalysisResult result = run(files);
        assertTrue(result.parseFailures().isEmpty(), "failures: " + result.parseFailures());
        assertEquals(1, result.findings().size(), () -> "field alias taint must reach sink: "
                + result.findings());
    }

    @Test
    void inheritanceAndOverloadingResolveToMostSpecificTarget() {
        Map<String, String> files = Map.of(
                "svc/com/x/Base.java", """
                        package com.x;
                        public class Base {
                            public String name() { return "base"; }
                        }
                        """,
                "svc/com/x/Child.java", """
                        package com.x;
                        public class Child extends Base {
                            public String readParam(String k) { return k; }
                            public void log(String q) { }

                            public void run() {
                                String p = readParam("p");
                                Child self = this;
                                self.log(p);
                            }
                        }
                        """);
        AnalysisResult result = run(files);
        assertTrue(result.parseFailures().isEmpty(), "failures: " + result.parseFailures());
        assertEquals(1, result.findings().size());
    }

    @Test
    void sanitizerCutsTaintThroughObjectMethods() {
        Map<String, String> files = Map.of(
                "s/com/S.java", """
                        package com.s;
                        public class S {
                            public String readParam(String k) { return k; }
                            public String escapeSql(String v) { return v; }
                            public void execute(String q) { }

                            public void m() {
                                String raw = readParam("r");
                                String safe = escapeSql(raw);
                                execute(safe);
                            }
                        }
                        """);
        AnalysisResult result = run(files);
        assertTrue(result.findings().isEmpty(), "sanitized flow must not alert");
    }

    @Test
    void staticMembersAreTrackedAcrossClasses() {
        Map<String, String> files = Map.of(
                "st/com/Cfg.java", """
                        package com.st;
                        public class Cfg {
                            public static String TOKEN;
                        }
                        """,
                "st/com/A.java", """
                        package com.st;
                        public class A {
                            public String readParam(String k) { return k; }
                            public void set() {
                                Cfg.TOKEN = readParam("t");
                            }
                        }
                        """,
                "st/com/B.java", """
                        package com.st;
                        public class B {
                            public void log(String q) { }
                            public void use() {
                                log(Cfg.TOKEN);
                            }
                        }
                        """);
        AnalysisResult result = run(files);
        assertTrue(result.parseFailures().isEmpty(), "failures: " + result.parseFailures());
        assertEquals(1, result.findings().size(),
                () -> "static field taint flows across classes: " + result.findings());
    }

    @Test
    void oneBrokenFileDoesNotStopOthersAndFailureIsStructured() {
        Map<String, String> files = new java.util.TreeMap<>();
        files.put("ok/com/Good.java", """
                package com;
                public class Good {
                    public String readParam(String k) { return k; }
                    public void log(String q) { }
                    public void m() { log(readParam("x")); }
                }
                """);
        files.put("bad/com/Bad.java", "package com; public class Bad { void m() { if ( } }");
        AnalysisResult result = run(files);
        assertEquals(1, result.parseFailures().size());
        ParseFailure failure = result.parseFailures().get(0);
        assertEquals("bad/com/Bad.java", failure.file());
        assertTrue(failure.line() >= 1);
        assertEquals(ParseFailure.SYNTAX, failure.reason());
        assertFalse(failure.message().isBlank());
        assertEquals(1, result.findings().size(), "good file still analyzed");
    }

    @Test
    void sameInputsAndRulesAreReproducible() {
        Map<String, String> files = Map.of(
                "r/com/R.java", """
                        package com;
                        public class R {
                            public String readParam(String k) { return k; }
                            public void execute(String q) { }
                            public void a() { execute(readParam("a")); }
                            public void b() { execute(readParam("b")); }
                        }
                        """);
        AnalysisResult r1 = run(files);
        AnalysisResult r2 = run(files);
        assertEquals(r1.findings(), r2.findings());
    }
}
