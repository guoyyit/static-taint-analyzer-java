package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.domain.AnalysisSnapshot;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.store.JobRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyCrashTest {

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

    private static final String SOURCE_V1 = """
            package demo;
            public class Dao {
                public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                    stmt.executeQuery(req.getParameter("q"));
                }
            }
            """;

    private static final String SOURCE_V2 = """
            package demo;
            public class Dao {
                public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                    stmt.executeQuery(req.getParameter("q"));
                    stmt.executeQuery(req.getParameter("q2"));
                }
            }
            """;

    @TempDir
    Path sourceDir;
    @TempDir
    Path dataDir;

    private AnalysisService service;

    @BeforeEach
    void setUp() throws IOException {
        Files.createDirectories(sourceDir.resolve("demo"));
        Files.writeString(sourceDir.resolve("demo/Dao.java"), SOURCE_V1);
        service = new AnalysisService(dataDir);
        service.ruleService().update(RULES, "test");
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    @Test
    void readersOnlySeeCompleteCommittedSnapshots() throws Exception {
        // Slow down commits so readers race with writers.
        service.setBeforeCommitHook(() -> {
            try {
                Thread.sleep(30);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        });

        List<String> violations = new CopyOnWriteArrayList<>();
        int readerThreads = 4;
        CountDownLatch stop = new CountDownLatch(1);
        ExecutorService readers = Executors.newFixedThreadPool(readerThreads);
        for (int i = 0; i < readerThreads; i++) {
            readers.submit(() -> {
                long lastVersion = -1;
                while (stop.getCount() > 0) {
                    AnalysisSnapshot snap = service.currentSnapshot();
                    if (snap.version() < lastVersion) {
                        violations.add("snapshot version went backwards: " + snap.version());
                    }
                    if (snap.findings() == null || snap.fileHashes() == null || snap.ruleHash() == null) {
                        violations.add("snapshot with null components observed");
                    }
                    for (Finding f : snap.findings()) {
                        if (f.lastSeenVersion() > snap.version()) {
                            violations.add("finding from the future leaked into snapshot " + snap.version());
                        }
                        if (!f.ruleHash().equals(snap.ruleHash())) {
                            violations.add("finding with foreign rule hash in snapshot " + snap.version());
                        }
                    }
                    lastVersion = snap.version();
                }
            });
        }

        // Writers: three sequential analyses with source changes in between.
        List<String> jobIds = new ArrayList<>();
        jobIds.add(service.submit(sourceDir.toString()));
        Files.writeString(sourceDir.resolve("demo/Dao.java"), SOURCE_V2);
        jobIds.add(service.submit(sourceDir.toString()));
        Files.writeString(sourceDir.resolve("demo/Dao2.java"), SOURCE_V1.replace("class Dao", "class Dao2"));
        jobIds.add(service.submit(sourceDir.toString()));
        for (String jobId : jobIds) {
            service.await(jobId);
        }

        stop.countDown();
        readers.shutdown();
        assertTrue(readers.awaitTermination(10, TimeUnit.SECONDS));

        assertTrue(violations.isEmpty(), () -> "consistency violations: " + violations);
        AnalysisSnapshot finalSnap = service.currentSnapshot();
        assertEquals(3, finalSnap.version(), "three commits must be visible");
        assertEquals(3, finalSnap.findings().size());
        for (String jobId : jobIds) {
            assertEquals(JobRecord.State.COMMITTED, service.job(jobId).orElseThrow().state());
        }
    }

    @Test
    void crashBeforeCommitIsRecoveredWithoutDuplicatesOrPartialWrites() throws Exception {
        // Arm the crash hook: the job dies right before the atomic commit.
        service.setBeforeCommitHook(() -> {
            throw new AnalysisService.SimulatedCrashException("boom before commit");
        });
        assertThrows(Exception.class, () -> service.submitAndWait(sourceDir.toString()));
        assertEquals(0, service.currentSnapshot().version(), "crashed job must not commit anything");
        assertEquals(0, countSnapshotFiles(), "no snapshot file may be written by the crashed job");

        // Simulate a restart: a fresh service over the same data dir recovers.
        AnalysisService restarted = new AnalysisService(dataDir);
        try {
            restarted.recover();
            AnalysisSnapshot snap = restarted.currentSnapshot();
            assertEquals(1, snap.version(), "recovery commits exactly one snapshot");
            assertEquals(1, snap.findings().size(), "recovered analysis is complete");
            assertEquals(1, countSnapshotFiles(), "no partial or duplicate snapshot files");
            long committed = restarted.jobs().stream()
                    .filter(j -> j.state() == JobRecord.State.COMMITTED).count();
            assertEquals(1, committed, "exactly one committed job after recovery");
            assertFalse(restarted.auditLog().events().isEmpty(), "recovery is auditable");
        } finally {
            restarted.shutdown();
        }
    }

    @Test
    void committedWorkIsNotRepeatedAfterRestart() throws Exception {
        service.submitAndWait(sourceDir.toString());
        assertEquals(1, service.currentSnapshot().version());

        AnalysisService restarted = new AnalysisService(dataDir);
        try {
            restarted.recover(); // nothing to redo: the only job is COMMITTED
            assertEquals(1, restarted.currentSnapshot().version(),
                    "committed snapshot survives restart unchanged");
            assertEquals(service.currentSnapshot().findings(), restarted.currentSnapshot().findings(),
                    "recovered findings identical to pre-crash committed findings");
        } finally {
            restarted.shutdown();
        }
    }

    private long countSnapshotFiles() throws IOException {
        Path snapshots = dataDir.resolve("snapshots");
        if (!Files.isDirectory(snapshots)) {
            return 0;
        }
        try (Stream<Path> files = Files.list(snapshots)) {
            return files.filter(f -> f.getFileName().toString().endsWith(".json")).count();
        }
    }
}
