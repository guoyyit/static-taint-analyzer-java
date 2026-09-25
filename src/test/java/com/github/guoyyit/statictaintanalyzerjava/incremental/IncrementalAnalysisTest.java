package com.github.guoyyit.statictaintanalyzerjava.incremental;

import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IncrementalAnalysisTest {

    private static final String RULES = """
            {
              "version": "1",
              "sources": [
                {"id": "http-param", "pattern": "javax.servlet.http.HttpServletRequest.getParameter", "risk": "HIGH"}
              ],
              "sinks": [
                {"id": "sql-exec", "pattern": "java.sql.Statement.executeQuery", "risk": "HIGH"}
              ],
              "sanitizers": []
            }
            """;

    private static final String A_TAINTED = """
            package demo;
            public class A {
                public String read(javax.servlet.http.HttpServletRequest req) {
                    return req.getParameter("name");
                }
            }
            """;

    private static final String A_CLEAN = """
            package demo;
            public class A {
                public String read(javax.servlet.http.HttpServletRequest req) {
                    return "constant";
                }
            }
            """;

    private static final String B_SINK = """
            package demo;
            public class B {
                public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                    A a = new A();
                    stmt.executeQuery(a.read(req));
                }
            }
            """;

    private static final String C_OWN_FLOW = """
            package demo;
            public class C {
                public void go(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                    stmt.executeQuery(req.getParameter("c"));
                }
            }
            """;

    @TempDir
    Path sourceDir;
    @TempDir
    Path dataDir;

    private AnalysisService service;

    @BeforeEach
    void setUp() {
        service = new AnalysisService(dataDir);
        service.ruleService().update(RULES, "test");
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    private void write(String name, String content) throws IOException {
        Files.createDirectories(sourceDir.resolve("demo"));
        Files.writeString(sourceDir.resolve("demo").resolve(name), content);
    }

    @Test
    void onlyAffectedPathsAreRecomputed() throws IOException {
        write("A.java", A_TAINTED);
        write("B.java", B_SINK);
        write("C.java", C_OWN_FLOW);
        service.submitAndWait(sourceDir.toString());

        List<Finding> v1 = service.currentSnapshot().findings();
        assertEquals(2, v1.size());
        Finding fromB = v1.stream().filter(f -> f.sinkMethodSignature().contains("B#")).findFirst().orElseThrow();
        Finding fromC = v1.stream().filter(f -> f.sinkMethodSignature().contains("C#")).findFirst().orElseThrow();
        assertEquals(1, fromB.firstSeenVersion());
        assertEquals(1, fromC.firstSeenVersion());

        // Change A so its return is no longer tainted; C is untouched.
        write("A.java", A_CLEAN);
        service.submitAndWait(sourceDir.toString());

        List<Finding> v2 = service.currentSnapshot().findings();
        assertEquals(2, service.currentSnapshot().version());
        // Affected path (through A) is gone: not missed, not kept stale.
        assertFalse(v2.stream().anyMatch(f -> f.fingerprint().equals(fromB.fingerprint())),
                "finding through changed method must be removed");
        // Unaffected path in C keeps identity: not falsely marked as changed.
        Finding cAgain = v2.stream().filter(f -> f.fingerprint().equals(fromC.fingerprint()))
                .findFirst().orElseThrow(() -> new AssertionError("unaffected finding must survive"));
        assertEquals(1, cAgain.firstSeenVersion(), "unaffected finding keeps original firstSeen");
        assertEquals(2, cAgain.lastSeenVersion());
    }

    @Test
    void newlyAffectedPathsAreNotMissed() throws IOException {
        write("A.java", A_CLEAN);
        write("B.java", B_SINK);
        service.submitAndWait(sourceDir.toString());
        assertTrue(service.currentSnapshot().findings().isEmpty());

        // Introduce taint in A: the cross-file path through B must now be reported.
        write("A.java", A_TAINTED);
        service.submitAndWait(sourceDir.toString());
        List<Finding> v2 = service.currentSnapshot().findings();
        assertEquals(1, v2.size(), "new cross-file taint path must not be missed");
        assertEquals(2, v2.get(0).firstSeenVersion());
    }

    @Test
    void identicalReanalysisIsFullyStable() throws IOException {
        write("A.java", A_TAINTED);
        write("B.java", B_SINK);
        write("C.java", C_OWN_FLOW);
        service.submitAndWait(sourceDir.toString());
        List<Finding> v1 = service.currentSnapshot().findings();

        service.submitAndWait(sourceDir.toString()); // no changes
        List<Finding> v2 = service.currentSnapshot().findings();

        // Path identity (fingerprint + steps) must be perfectly reproducible.
        assertEquals(v1.stream().map(Finding::fingerprint).toList(),
                v2.stream().map(Finding::fingerprint).toList(),
                "same input + same rules must reproduce identical fingerprints");
        assertEquals(v1.stream().map(Finding::path).toList(),
                v2.stream().map(Finding::path).toList(),
                "same input + same rules must reproduce identical paths");
        assertTrue(v2.stream().allMatch(f -> f.firstSeenVersion() == 1),
                "unchanged findings keep firstSeen from the first snapshot");
    }
}
