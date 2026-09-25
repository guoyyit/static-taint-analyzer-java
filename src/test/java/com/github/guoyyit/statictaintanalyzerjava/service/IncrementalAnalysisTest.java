package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;
import com.github.guoyyit.statictaintanalyzerjava.analysis.Finding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class IncrementalAnalysisTest {

    private static final String RULES = """
            {
              "sources": [{"id":"user-input","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
              "sanitizers": [{"id":"escape","pattern":"escapeSql"}]
            }
            """;

    private static final String FILE_A = """
            fn a() {
              x = readParam("x");
              executeSql(x);
            }
            """;

    private static final String FILE_B = """
            fn b() {
              y = readParam("y");
              executeSql(y);
            }
            """;

    @TempDir
    Path dataDir;

    private AnalysisService service;

    @BeforeEach
    void setUp() {
        service = new AnalysisService(dataDir);
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    private String submitAndWait(Map<String, String> files, String rules, String jobId) {
        String id = service.submit("proj", files, rules, jobId);
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            AnalysisService.JobView view = service.jobStatus("proj", id);
            if (view.status() == AnalysisService.JobStatus.COMMITTED) {
                return view.commitId();
            }
            if (view.status() == AnalysisService.JobStatus.FAILED) {
                fail("job failed: " + view.error());
            }
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail();
            }
        }
        fail("job did not commit in time");
        return null;
    }

    @Test
    void onlyChangedFilesAreReparsedAndUnchangedPathsStayUnchanged() {
        String c1 = submitAndWait(Map.of("a.req", FILE_A, "b.req", FILE_B), RULES, "job-1");
        AnalysisResult r1 = service.commitResult("proj", c1).orElseThrow();
        assertEquals(2, r1.findings().size());
        assertEquals(0, r1.stats().reusedFiles());
        assertEquals(2, r1.stats().reparsedFiles());

        // change only a.req: add a second sink call
        String fileA2 = FILE_A + """
                fn a2() {
                  z = readParam("z");
                  executeSql(z);
                }
                """;
        String c2 = submitAndWait(Map.of("a.req", fileA2, "b.req", FILE_B), RULES, "job-2");
        AnalysisResult r2 = service.commitResult("proj", c2).orElseThrow();

        assertEquals(1, r2.stats().reusedFiles(), "b.req must be reused from cache");
        assertEquals(1, r2.stats().reparsedFiles(), "only a.req must be re-parsed");
        assertEquals(3, r2.findings().size());

        Set<String> bFingerprints = r1.findings().stream()
                .filter(f -> f.path().stream().anyMatch(s -> s.file().equals("b.req")))
                .map(Finding::fingerprint).collect(Collectors.toSet());
        Map<String, Finding> r2ByFp = r2.findings().stream()
                .collect(Collectors.toMap(Finding::fingerprint, f -> f));
        for (String fp : bFingerprints) {
            Finding carried = r2ByFp.get(fp);
            assertNotNull(carried, "unaffected path must not be lost");
            assertEquals(Finding.STATUS_UNCHANGED, carried.status(),
                    "unaffected path must not be marked as changed");
        }
        long newCount = r2.findings().stream().filter(f -> f.status().equals(Finding.STATUS_NEW)).count();
        assertEquals(1, newCount, "exactly the added path is NEW");
    }

    @Test
    void removedPathsAreReported() {
        submitAndWait(Map.of("a.req", FILE_A, "b.req", FILE_B), RULES, "job-1");
        String c2 = submitAndWait(Map.of("a.req", FILE_A, "b.req", """
                fn b() {
                  y = readParam("y");
                  safe = escapeSql(y);
                  executeSql(safe);
                }
                """), RULES, "job-2");
        AnalysisService.FindingsView view = service.commitFindings("proj", c2);
        assertEquals(1, view.findings().size());
        assertEquals(1, view.removedFingerprints().size(), "sanitized path must be reported removed");
    }

    @Test
    void ruleChangesNeverMixWithOldResults() {
        String c1 = submitAndWait(Map.of("a.req", FILE_A), RULES, "job-1");
        String newRules = """
                {
                  "sources": [{"id":"user-input","pattern":"readParam","severity":"LOW"}],
                  "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"MEDIUM"}],
                  "sanitizers": []
                }
                """;
        String c2 = submitAndWait(Map.of("a.req", FILE_A), newRules, "job-2");
        AnalysisResult r1 = service.commitResult("proj", c1).orElseThrow();
        AnalysisResult r2 = service.commitResult("proj", c2).orElseThrow();

        assertNotEquals(r1.rulesHash(), r2.rulesHash(), "each commit binds its own rules hash");
        assertEquals(0, r2.stats().reusedFiles(), "rule change invalidates all cached summaries");
        assertEquals(1, r2.stats().reparsedFiles());
        // old commit still reflects old rules, new commit reflects new rules
        assertEquals("CRITICAL", r1.findings().get(0).severity().name());
        assertEquals("MEDIUM", r2.findings().get(0).severity().name());
    }
}
