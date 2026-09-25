package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.Finding;
import com.github.guoyyit.statictaintanalyzerjava.store.AuditLog;
import com.github.guoyyit.statictaintanalyzerjava.store.ExemptionStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExemptionTest {

    private static final String RULES = """
            {
              "sources": [{"id":"user-input","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    private static final Map<String, String> FILES = Map.of("a.req", """
            fn a() {
              x = readParam("x");
              executeSql(x);
            }
            """);

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

    private String commitOne(String rules, String jobId) {
        String id = service.submit("proj", FILES, rules, jobId);
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            AnalysisService.JobView view = service.jobStatus("proj", id);
            if (view.status() == AnalysisService.JobStatus.COMMITTED) {
                return view.commitId();
            }
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail();
            }
        }
        fail("job did not commit");
        return null;
    }

    private String onlyFingerprint() {
        List<Finding> findings = service.currentFindings("proj").findings();
        assertEquals(1, findings.size());
        return findings.get(0).fingerprint();
    }

    @Test
    void activeExemptionSuppressesFinding() {
        commitOne(RULES, "job-1");
        String fp = onlyFingerprint();
        service.exempt("proj", fp, "accepted risk", "alice", null);
        assertTrue(service.currentFindings("proj").suppressedFingerprints().contains(fp));
    }

    @Test
    void expiredExemptionRestoresDetection() {
        commitOne(RULES, "job-1");
        String fp = onlyFingerprint();
        Instant past = Instant.now().minus(1, ChronoUnit.HOURS);
        service.exempt("proj", fp, "stale waiver", "bob", past);
        assertFalse(service.currentFindings("proj").suppressedFingerprints().contains(fp),
                "expired exemption must not suppress");
    }

    @Test
    void revokedExemptionRestoresDetection() {
        commitOne(RULES, "job-1");
        String fp = onlyFingerprint();
        ExemptionStore.Exemption e = service.exempt("proj", fp, "temp", "carol", null);
        assertTrue(service.currentFindings("proj").suppressedFingerprints().contains(fp));
        service.revokeExemption("proj", e.id(), "carol");
        assertFalse(service.currentFindings("proj").suppressedFingerprints().contains(fp));
    }

    @Test
    void ruleChangeInvalidatesExemption() {
        commitOne(RULES, "job-1");
        String fp = onlyFingerprint();
        service.exempt("proj", fp, "accepted", "dave", null);
        assertTrue(service.currentFindings("proj").suppressedFingerprints().contains(fp));

        String newRules = """
                {
                  "sources": [{"id":"user-input","pattern":"readParam","severity":"MEDIUM"}],
                  "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
                  "sanitizers": []
                }
                """;
        commitOne(newRules, "job-2");
        assertFalse(service.currentFindings("proj").suppressedFingerprints().contains(fp),
                "exemption bound to old rules hash must not suppress under new rules");
    }

    @Test
    void allMutationsAreAudited() {
        commitOne(RULES, "job-1");
        String fp = onlyFingerprint();
        ExemptionStore.Exemption e = service.exempt("proj", fp, "accepted", "erin", null);
        service.revokeExemption("proj", e.id(), "erin");

        List<String> actions = service.audit("proj").stream().map(AuditLog.AuditEvent::action).toList();
        assertTrue(actions.contains("ANALYSIS_COMMITTED"));
        assertTrue(actions.contains("EXEMPTION_CREATED"));
        assertTrue(actions.contains("EXEMPTION_REVOKED"));
        // audit events are ordered by sequence
        List<Long> seqs = service.audit("proj").stream().map(AuditLog.AuditEvent::seq).toList();
        assertEquals(seqs.stream().sorted().toList(), seqs);
    }

    @Test
    void rulesChangeIsAudited() {
        commitOne(RULES, "job-1");
        String newRules = """
                {
                  "sources": [{"id":"user-input","pattern":"readParam","severity":"LOW"}],
                  "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
                  "sanitizers": []
                }
                """;
        commitOne(newRules, "job-2");
        List<String> actions = service.audit("proj").stream().map(AuditLog.AuditEvent::action).toList();
        assertTrue(actions.contains("RULES_CHANGED"));
    }
}
