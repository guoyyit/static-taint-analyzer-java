package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JavaSmokeTest {

    private static final String RULES = """
            {
              "sources": [{"id":"user-input","pattern":"com.acme.WebUtil#readParam","severity":"HIGH"}],
              "sinks": [{"id":"sql-exec","pattern":"com.acme.db.*","severity":"CRITICAL"}],
              "sanitizers": [{"id":"escape","pattern":"escapeSql"}]
            }
            """;

    private final AnalysisEngine engine = new AnalysisEngine();

    private AnalysisResult analyze(Map<String, String> files) {
        return engine.analyze(files, AnalysisRules.fromJson(RULES), null);
    }

    private AnalysisResult analyze(Map<String, String> files, AnalysisRules rules) {
        return engine.analyze(files, rules, null);
    }

    @Test
    void crossClassCrossPackageTaint() {
        Map<String, String> files = Map.of(
                "com/acme/Handler.java", """
                        package com.acme;
                        import com.acme.dao.QueryBuilder;
                        import com.acme.db.Jdbc;
                        public class Handler {
                          public void handle() {
                            String name = WebUtil.readParam("name");
                            QueryBuilder qb = new QueryBuilder();
                            String sql = qb.build(name);
                            Jdbc.executeSql(sql);
                          }
                        }
                        """,
                "com/acme/dao/QueryBuilder.java", """
                        package com.acme.dao;
                        public class QueryBuilder {
                          public String build(String n) {
                            return "SELECT * FROM u WHERE n=" + n;
                          }
                        }
                        """,
                "com/acme/WebUtil.java", """
                        package com.acme;
                        public class WebUtil {
                          public static String readParam(String key) { return key; }
                        }
                        """,
                "com/acme/db/Jdbc.java", """
                        package com.acme.db;
                        public class Jdbc {
                          public static void executeSql(String q) { }
                        }
                        """);
        AnalysisResult result = analyze(files);
        System.out.println("FINDINGS=" + result.findings().size());
        result.findings().forEach(f -> System.out.println(f.path()));
        assertEquals(1, result.findings().size(), "one cross-class finding expected");
        Finding f = result.findings().get(0);
        assertEquals("user-input", f.sourceRuleId());
        assertEquals("sql-exec", f.sinkRuleId());
    }

    @Test
    void fieldAliasAndInheritance() {
        Map<String, String> files = Map.of(
                "A.java", """
                        package p;
                        import p.db.Sink;
                        public class A extends Base {
                          public void run() {
                            String x = Sink.input();
                            this.name = x;
                            Sink.log(this.name);
                          }
                        }
                        """,
                "Base.java", """
                        package p;
                        public class Base {
                          protected String name;
                        }
                        """,
                "db/Sink.java", """
                        package p.db;
                        public class Sink {
                          public static String input() { return ""; }
                          public static void log(String s) { }
                        }
                        """);
        String rules = """
            {
              "sources": [{"id":"in","pattern":"p.db.Sink#input","severity":"HIGH"}],
              "sinks": [{"id":"log","pattern":"p.db.Sink#log","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        System.out.println("ALIAS FINDINGS=" + result.findings().size());
        result.findings().forEach(f -> System.out.println(f.path()));
        assertEquals(1, result.findings().size());
    }

    @Test
    void parseFailureIsolation() {
        Map<String, String> files = Map.of(
                "Good.java", """
                        package p;
                        public class Good {
                          public void ok() { int a = 1; }
                        }
                        """,
                "Bad.java", "package p;\npublic class Bad { public void oops( { }\n");
        AnalysisResult result = engine.analyze(files, AnalysisRules.fromJson(
                "{\"sources\":[],\"sinks\":[],\"sanitizers\":[]}"), null);
        assertEquals(1, result.parseFailures().size());
        assertEquals("Bad.java", result.parseFailures().get(0).file());
        assertTrue(result.parseFailures().get(0).line() >= 1);
        assertEquals("SYNTAX_ERROR", result.parseFailures().get(0).code());
        assertTrue(result.stats().failedFiles() == 1);
    }

    @Test
    void constructorCarriesTaintIntoObjectField() {
        Map<String, String> files = Map.of(
                "Main.java", """
                        package p;
                        public class Main {
                          public void go() {
                            String u = Source.get();
                            Holder h = new Holder(u);
                            Sink.run(h.value);
                          }
                        }
                        """,
                "Holder.java", """
                        package p;
                        public class Holder {
                          String value;
                          Holder(String v) { this.value = v; }
                        }
                        """,
                "Source.java", """
                        package p;
                        public class Source { static String get() { return ""; } }
                        """,
                "Sink.java", """
                        package p;
                        public class Sink { static void run(String s) { } }
                        """);
        String rules = """
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        result.findings().forEach(f -> System.out.println("CTOR " + f.path()));
        assertEquals(1, result.findings().size(), "constructor must carry arg taint into object field");
    }

    @Test
    void overloadResolutionByArity() {
        Map<String, String> files = Map.of(
                "Main.java", """
                        package p;
                        public class Main {
                          public void go() {
                            String u = Source.get();
                            String r = Calc.fmt(u);
                            Sink.run(r);
                          }
                        }
                        """,
                "Calc.java", """
                        package p;
                        public class Calc {
                          public static String fmt(int n) { return "n"; }
                          public static String fmt(String s) { return "[" + s + "]"; }
                          public static String fmt(String a, String b) { return a + b; }
                        }
                        """,
                "Source.java", """
                        package p;
                        public class Source { static String get() { return ""; } }
                        """,
                "Sink.java", """
                        package p;
                        public class Sink { static void run(String s) { } }
                        """);
        String rules = """
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        assertEquals(1, result.findings().size(),
                "must resolve the (String) overload, not the 2-arg/int ones: " + result.findings().size());
        // path must step into p.Calc#fmt(String)
        String functions = result.findings().get(0).path().stream()
                .map(st -> st.function()).toList().toString();
        assertTrue(functions.contains("p.Calc#fmt(String)"), functions);
        assertFalse(functions.contains("p.Calc#fmt(String,String)"), functions);
    }

    @Test
    void recursionAndLoopsBoundedAndDeterministic() {
        Map<String, String> files = Map.of("Main.java", """
                package p;
                public class Main {
                  public void go() {
                    String u = Source.get();
                    String r = loop(u, 3);
                    for (int i = 0; i < 10; i++) { r = r + u; }
                    Sink.run(r);
                  }
                  public String loop(String x, int n) {
                    if (n <= 0) { return x; }
                    return loop(x, n - 1);
                  }
                }
                """,
                "Source.java", "package p; public class Source { static String get(){return \"\";} }",
                "Sink.java", "package p; public class Sink { static void run(String s){} }");
        String rules = """
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        AnalysisRules rr = AnalysisRules.fromJson(rules);
        AnalysisResult a = engine.analyze(files, rr, null);
        AnalysisResult b = engine.analyze(files, rr, null);
        assertEquals(a.findings(), b.findings(), "deterministic");
        assertEquals(1, a.findings().size());
        assertTrue(a.findings().get(0).path().size() <= TaintEngine.MAX_PATH_LENGTH);
    }

    @Test
    void ruleChangeReanalyzesAndSwapsFindings() {
        Map<String, String> files = Map.of("Main.java", """
                package p;
                public class Main {
                  public void go() {
                    String u = Source.get();
                    String s = San.clean(u);
                    Sink.run(s);
                  }
                }
                """,
                "Source.java", "package p; public class Source { static String get(){return \"\";} }",
                "San.java", "package p; public class San { static String clean(String x){return x;} }",
                "Sink.java", "package p; public class Sink { static void run(String s){} }");
        AnalysisRules withSanitizer = AnalysisRules.fromJson("""
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": [{"id":"c","pattern":"p.San#clean"}]
            }
            """);
        AnalysisResult r1 = engine.analyze(files, withSanitizer, null);
        assertTrue(r1.findings().isEmpty(), "sanitizer blocks");
        AnalysisRules noSanitizer = AnalysisRules.fromJson("""
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """);
        AnalysisResult r2 = engine.analyze(files, noSanitizer, r1);
        assertEquals(1, r2.findings().size(), "rule change re-enables the path");
        assertEquals(0, r2.stats().reusedFiles(), "rule change invalidates summaries");
    }

    @Test
    void distinctFailureReasons() {
        var frontend = new com.github.guoyyit.statictaintanalyzerjava.lang.JavaFrontend();
        // syntax error
        var se = assertThrows(com.github.guoyyit.statictaintanalyzerjava.lang.JavaParseException.class,
                () -> frontend.summarizeFile("S.java",
                        "package p; public class S { void m( { }"));
        assertEquals("SYNTAX_ERROR", se.failure().code());
        assertEquals("S.java", se.failure().file());
        assertTrue(se.failure().line() >= 1);
        // lexical error: illegal character '#' is a TokenMgrException
        var le = assertThrows(com.github.guoyyit.statictaintanalyzerjava.lang.JavaParseException.class,
                () -> frontend.summarizeFile("L.java",
                        "package p; public class L { void m(){ #; } }"));
        assertEquals("LEXICAL_ERROR", le.failure().code());
        assertEquals("L.java", le.failure().file());
        assertTrue(le.failure().line() >= 1);
    }

    @Test
    void largeProjectIsBounded() {
        Map<String, String> files = new java.util.TreeMap<>();
        files.put("s/Source.java", "package s; public class Source { public static String get(){return \"\";} }");
        files.put("t/Sink.java", "package t; import s.Source; public class Sink { public static void run(String x){} }");
        int classes = 120;
        for (int i = 0; i < classes; i++) {
            String pkg = "p" + (i % 8);
            String prev = i == 0 ? "Source.get()" : ("C" + (i - 1) + ".get()");
            String prevPkg = i == 0 ? "s" : "p" + ((i - 1) % 8);
            String imp = i == 0 ? "import s.Source;" : "import " + prevPkg + ".C" + (i - 1) + ";";
            files.put(pkg + "/C" + i + ".java", """
                    package %s;
                    %s
                    public class C%d {
                      public static String get() {
                        String v = %s;
                        for (int k = 0; k < 50; k++) { v = v + k; }
                        return v;
                      }
                    }
                    """.formatted(pkg, imp, i, prev));
        }
        // a class chain crossing packages to the sink
        files.put("app/App.java", """
                package app;
                import p7.C119;
                import t.Sink;
                public class App {
                  public void go() { Sink.run(C119.get()); }
                }
                """);
        String rules = """
            {
              "sources": [{"id":"in","pattern":"s.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"t.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        long start = System.currentTimeMillis();
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        long elapsed = System.currentTimeMillis() - start;
        System.out.println("large project ms=" + elapsed + " findings=" + result.findings().size());
        assertTrue(elapsed < 20_000, "analysis must be bounded, took " + elapsed);
        assertEquals(1, result.findings().size(), "taint crosses 120 classes / 8 packages");
    }

    @Test
    void wildcardPrefixRulesMatchJavaPackages() {
        Map<String, String> files = Map.of(
                "Main.java", """
                        package app;
                        import com.acme.in.Http;
                        import com.acme.out.sql.Query;
                        public class Main {
                          public void go() {
                            String u = Http.param();
                            Query.exec(u);
                          }
                        }
                        """,
                "Http.java", "package com.acme.in; public class Http { public static String param(){return \"\";} }",
                "Query.java", "package com.acme.out.sql; public class Query { public static void exec(String s){} }");
        String rules = """
            {
              "sources": [{"id":"in","pattern":"com.acme.in.*","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"com.acme.out.*","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        assertEquals(1, result.findings().size(), "wildcard package prefix must match Java calls");
    }

    @Test
    void superCallStaticFieldAndInterfaceDefault() {
        Map<String, String> files = Map.of(
            "Main.java", """
                    package p;
                    public class Main extends Child {
                      public void go() {
                        String u = S.in();
                        this.req = u;
                        work();
                      }
                    }
                    """,
            "Child.java", """
                    package p;
                    public class Child extends Base implements I {
                    }
                    """,
            "Base.java", """
                    package p;
                    public class Base {
                      protected String req;
                      public void work() {
                        String q = "SELECT " + this.req;
                        S.out(q);
                      }
                    }
                    """,
            "I.java", """
                    package p;
                    public interface I {
                      default void noop() { }
                    }
                    """,
            "S.java", """
                    package p;
                    public class S {
                      public static String MARK = "";
                      public static String in() { return MARK; }
                      public static void out(String s) { }
                    }
                    """);
        String rules = """
            {
              "sources": [{"id":"in","pattern":"p.S#in","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.S#out","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        result.findings().forEach(f -> System.out.println("SUPER " + f.path()));
        assertEquals(1, result.findings().size(),
                "taint via field, superclass method and string concat: " + result.findings().size());
    }

    @Test
    void objectAliasesShareFieldTaint() {
        Map<String, String> files = Map.of(
            "Main.java", """
                    package p;
                    public class Main {
                      public void go() {
                        Holder a = new Holder();
                        Holder b = a;                 // alias
                        String u = S.in();
                        b.value = u;                  // mutate through one alias
                        S.out(a.value);               // read through the other
                      }
                    }
                    """,
            "Holder.java", """
                    package p;
                    public class Holder { String value; }
                    """,
            "S.java", "package p; public class S { static String in(){return \"\";} static void out(String s){} }");
        String rules = """
            {"sources":[{"id":"in","pattern":"p.S#in","severity":"HIGH"}],
             "sinks":[{"id":"out","pattern":"p.S#out","severity":"CRITICAL"}],"sanitizers":[]}
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        result.findings().forEach(f -> System.out.println("ALIAS2 " + f.path()));
        assertEquals(1, result.findings().size(),
                "aliases a and b refer to the same object field: " + result.findings().size());
    }

    @Test
    void nestedCallsForEachAndTernaryCarryTaint() {
        Map<String, String> files = Map.of(
            "Main.java", """
                    package p;
                    import java.util.List;
                    public class Main {
                      public void go(List<String> items, boolean flag) {
                        String u = S.in();
                        String wrapped = Util.wrap(u);          // nested target
                        for (String item : items) {
                            String v = flag ? wrapped : item;    // ternary + loop
                            S.out(Util.wrap(v));                 // call-as-argument
                        }
                      }
                    }
                    """,
            "Util.java", "package p; public class Util { static String wrap(String x){ return x; } }",
            "S.java", "package p; public class S { static String in(){return \"\";} static void out(String s){} }");
        String rules = """
            {"sources":[{"id":"in","pattern":"p.S#in","severity":"HIGH"}],
             "sinks":[{"id":"out","pattern":"p.S#out","severity":"CRITICAL"}],"sanitizers":[]}
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        result.findings().forEach(f -> System.out.println("NESTED count via wrapped: "+f.path().size()));
        assertFalse(result.findings().isEmpty(),
                "taint must survive nested calls, ternary and for-each");
        // determinism
        assertEquals(result.findings(), analyze(files, AnalysisRules.fromJson(rules)).findings());
    }

    @Test
    void chainedMethodCallsAcrossReturnedObjects() {
        Map<String, String> files = Map.of(
            "Main.java", """
                    package p;
                    public class Main {
                      public void go() {
                        String u = S.in();
                        Builder b = Factory.make();
                        S.out(b.add(u).build());
                      }
                    }
                    """,
            "Factory.java", "package p; public class Factory { static Builder make(){return new Builder();} }",
            "Builder.java", """
                    package p;
                    public class Builder {
                      private String acc = "";
                      public Builder add(String x){ this.acc = this.acc + x; return this; }
                      public String build(){ return "q" + this.acc; }
                    }
                    """,
            "S.java", "package p; public class S { static String in(){return \"\";} static void out(String s){} }");
        String rules = """
            {"sources":[{"id":"in","pattern":"p.S#in","severity":"HIGH"}],
             "sinks":[{"id":"out","pattern":"p.S#out","severity":"CRITICAL"}],"sanitizers":[]}
            """;
        AnalysisResult result = analyze(files, AnalysisRules.fromJson(rules));
        result.findings().forEach(f -> System.out.println("CHAIN "+f.path()));
        // Conservative: unresolved chained return still propagates arg taint to sink.
        assertFalse(result.findings().isEmpty(), "chained calls must conservatively propagate");
    }
}
