package com.github.guoyyit.statictaintanalyzerjava.exemption;

import com.github.guoyyit.statictaintanalyzerjava.domain.AuditEvent;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExemptionTest {

    private static final String RULES_V1 = """
            {
              "version": "1",
              "sources": [
                {"id": "http-param", "pattern": "javax.servlet.http.HttpServletRequest.getParameter", "risk": "HIGH"}
              ],
              "sinks": [
                {"id": "sql-exec", "pattern": "java.sql.Statement.executeQuery", "risk": "HIGH", "message": "sqli"}
              ],
              "sanitizers": []
            }
            """;

    private static final String RULES_V2 = RULES_V1.replace("\"1\"", "\"2\"")
            .replace("sqli", "sql injection");

    private static final String SOURCE = """
            package demo;
            public class Dao {
                public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                    stmt.executeQuery(req.getParameter("q"));
                }
            }
            """;

    @TempDir
    Path sourceDir;
    @TempDir
    Path dataDir;

    private final AtomicReference<Instant> clock =
            new AtomicReference<>(Instant.parse("2026-09-25T00:00:00Z"));
    private AnalysisService service;

    @BeforeEach
    void setUp() throws IOException {
        Files.createDirectories(sourceDir.resolve("demo"));
        Files.writeString(sourceDir.resolve("demo/Dao.java"), SOURCE);
        service = new AnalysisService(dataDir, clock::get);
        service.ruleService().update(RULES_V1, "test");
        service.submitAndWait(sourceDir.toString());
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    private Finding theFinding() {
        List<Finding> all = service.queryFindings(null, true);
        assertEquals(1, all.size());
        return all.get(0);
    }

    @Test
    void exemptionSuppressesAndExpiryRestores() {
        Finding f = theFinding();
        assertEquals(1, service.queryFindings(null, false).size(), "no exemption yet");

        service.exemptionService().create(f.fingerprint(), "accepted risk", "auditor",
                clock.get().plus(1, ChronoUnit.HOURS), service.ruleService().current().hash());
        assertTrue(service.queryFindings(null, false).isEmpty(), "exempted finding must not alert");
        assertEquals(1, service.queryFindings(null, true).size(), "still visible when requested");

        // Time passes beyond expiry: detection resumes without any re-analysis.
        clock.set(clock.get().plus(2, ChronoUnit.HOURS));
        assertEquals(1, service.queryFindings(null, false).size(), "expired exemption must restore detection");
    }

    @Test
    void ruleChangeInvalidatesExemption() {
        Finding f = theFinding();
        service.exemptionService().create(f.fingerprint(), "accepted risk", "auditor",
                null, service.ruleService().current().hash());
        assertTrue(service.queryFindings(null, false).isEmpty());

        // Rules change: findings are recomputed under the new rule hash and the
        // old exemption no longer applies.
        service.ruleService().update(RULES_V2, "test");
        service.submitAndWait(sourceDir.toString());
        assertEquals(1, service.queryFindings(null, false).size(),
                "rule change must restore detection despite exemption");
    }

    @Test
    void allExemptionOperationsAreAudited() {
        Finding f = theFinding();
        var exemption = service.exemptionService().create(f.fingerprint(), "fp", "auditor",
                null, service.ruleService().current().hash());
        service.exemptionService().revoke(exemption.id(), "auditor");
        assertEquals(1, service.queryFindings(null, false).size(), "revoked exemption restores alert");

        List<AuditEvent> events = service.auditLog().events();
        assertTrue(events.stream().anyMatch(e -> e.type().equals("EXEMPTION_CREATED") && e.actor().equals("auditor")));
        assertTrue(events.stream().anyMatch(e -> e.type().equals("EXEMPTION_REVOKED") && e.actor().equals("auditor")));
        assertTrue(events.stream().anyMatch(e -> e.type().equals("ANALYSIS_COMMITTED")));
        assertTrue(events.stream().anyMatch(e -> e.type().equals("RULES_UPDATED")));
    }

    @Test
    void baselineSeparatesNewFindings() throws IOException {
        assertEquals(1, service.findingsNewSinceBaseline().size(), "no baseline: everything is new");
        service.markBaseline("test");
        assertTrue(service.findingsNewSinceBaseline().isEmpty(), "baseline covers existing findings");

        // Introduce a second tainted flow and re-analyze.
        Files.writeString(sourceDir.resolve("demo/Dao2.java"), """
                package demo;
                public class Dao2 {
                    public void go(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                        stmt.executeQuery(req.getParameter("x"));
                    }
                }
                """);
        service.submitAndWait(sourceDir.toString());
        List<Finding> newOnes = service.findingsNewSinceBaseline();
        assertEquals(1, newOnes.size(), "only the newly introduced path is new-since-baseline");
        assertTrue(newOnes.get(0).sinkMethodSignature().contains("Dao2#"));
        assertFalse(service.queryFindings(null, false).isEmpty());
    }
}
