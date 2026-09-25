package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TaintEngineTest {

    private static final String RULES = """
            {
              "sources": [{"id":"user-input","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
              "sanitizers": [{"id":"escape","pattern":"escapeSql"}]
            }
            """;

    private final AnalysisEngine engine = new AnalysisEngine();

    private AnalysisResult analyze(Map<String, String> files) {
        return engine.analyze(files, AnalysisRules.fromJson(RULES), null);
    }

    @Test
    void propagatesAcrossFunctions() {
        Map<String, String> files = Map.of(
                "web.req", """
                        fn handle() {
                          name = readParam("name");
                          sql = buildQuery(name);
                          executeSql(sql);
                        }
                        """,
                "dal.req", """
                        fn buildQuery(n) {
                          q = "SELECT * FROM u WHERE n=" + n;
                          return q;
                        }
                        """);
        AnalysisResult result = analyze(files);
        assertEquals(1, result.findings().size(), "expected one cross-function finding");
        Finding f = result.findings().get(0);
        assertEquals("user-input", f.sourceRuleId());
        assertEquals("sql-exec", f.sinkRuleId());
        // path must traverse both functions: source in handle, through buildQuery, back to sink
        List<String> functions = f.path().stream().map(Finding.Step::function).distinct().toList();
        assertTrue(functions.contains("handle") && functions.contains("buildQuery"),
                "path should span functions: " + functions);
    }

    @Test
    void sanitizerBlocksTaint() {
        Map<String, String> files = Map.of("a.req", """
                fn handle() {
                  name = readParam("name");
                  safe = escapeSql(name);
                  executeSql(safe);
                }
                """);
        assertTrue(analyze(files).findings().isEmpty(), "sanitized value must not alert");
    }

    @Test
    void sanitizerBypassStillAlerts() {
        Map<String, String> files = Map.of("a.req", """
                fn handle() {
                  name = readParam("name");
                  safe = escapeSql(name);
                  executeSql(name);
                }
                """);
        assertEquals(1, analyze(files).findings().size(),
                "unsanitized copy must still alert even though a sanitized copy exists");
    }

    @Test
    void recursionAndLoopsAreBounded() {
        Map<String, String> files = Map.of("a.req", """
                fn handle() {
                  name = readParam("name");
                  r = recur(name);
                  i = 0;
                  acc = r;
                  while (i) {
                    acc = acc + r;
                    i = i + 1;
                  }
                  executeSql(acc);
                }
                fn recur(x) {
                  if (x) {
                    return x;
                  } else {
                    return recur(x);
                  }
                }
                """);
        AnalysisResult result = analyze(files);
        assertEquals(1, result.findings().size());
        assertTrue(result.findings().get(0).path().size() <= TaintEngine.MAX_PATH_LENGTH);
    }

    @Test
    void resultsAreDeterministic() {
        Map<String, String> files = Map.of(
                "a.req", """
                        fn a() {
                          x = readParam("x");
                          y = mid(x);
                          executeSql(y);
                        }
                        """,
                "b.req", """
                        fn mid(v) {
                          return v;
                        }
                        fn b() {
                          z = readParam("z");
                          executeSql(z);
                        }
                        """);
        AnalysisResult r1 = analyze(files);
        AnalysisResult r2 = analyze(files);
        assertEquals(r1.findings(), r2.findings(), "same input must reproduce identical findings");
        assertEquals(2, r1.findings().size());
        // sorted by risk: equal severity -> shorter path first
        assertTrue(r1.findings().get(0).path().size() <= r1.findings().get(1).path().size());
    }
}
