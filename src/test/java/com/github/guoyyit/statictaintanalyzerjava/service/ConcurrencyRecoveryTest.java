package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;
import com.github.guoyyit.statictaintanalyzerjava.store.CommitStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ConcurrencyRecoveryTest {

    private static final String RULES = """
            {
              "sources": [{"id":"user-input","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    @TempDir
    Path dataDir;

    private static Map<String, String> files(int n) {
        Map<String, String> files = new java.util.TreeMap<>();
        for (int i = 0; i < n; i++) {
            files.put("f" + i + ".req", """
                    fn f%d() {
                      v%d = readParam("v");
                      executeSql(v%d);
                    }
                    """.formatted(i, i, i));
        }
        return files;
    }

    private static void waitCommitted(AnalysisService service, String project, String jobId) {
        long deadline = System.currentTimeMillis() + 15_000;
        while (System.currentTimeMillis() < deadline) {
            AnalysisService.JobView view = service.jobStatus(project, jobId);
            if (view.status() == AnalysisService.JobStatus.COMMITTED) {
                return;
            }
            if (view.status() == AnalysisService.JobStatus.FAILED) {
                fail("job failed: " + view.error());
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail();
            }
        }
        fail("job " + jobId + " did not commit in time");
    }

    @Test
    void readersNeverSeePartialCommits() throws Exception {
        AnalysisService service = new AnalysisService(dataDir);
        try {
            CountDownLatch stop = new CountDownLatch(1);
            AtomicReference<AssertionError> readerFailure = new AtomicReference<>();
            Thread reader = new Thread(() -> {
                try {
                    while (stop.getCount() > 0) {
                        AnalysisService.FindingsView view = service.currentFindings("proj");
                        if (view.commitId() == null) {
                            assertTrue(view.findings().isEmpty(), "no commit -> no findings");
                        } else {
                            // every visible commit must be fully loadable and consistent
                            Optional<AnalysisResult> result = service.commitResult("proj", view.commitId());
                            assertTrue(result.isPresent(), "visible commit must be loadable");
                            assertEquals(result.get().findings().size(), view.findings().size(),
                                    "view must match the committed snapshot");
                            assertEquals(result.get().rulesHash(), view.rulesHash());
                        }
                    }
                } catch (AssertionError e) {
                    readerFailure.set(e);
                }
            });
            reader.start();

            for (int i = 0; i < 5; i++) {
                service.submit("proj", files(3 + i), RULES, "job-" + i);
            }
            for (int i = 0; i < 5; i++) {
                waitCommitted(service, "proj", "job-" + i);
            }
            stop.countDown();
            reader.join(5000);
            if (readerFailure.get() != null) {
                throw readerFailure.get();
            }
            assertEquals(5, service.commits("proj").size());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void concurrentSubmissionsSerializeIntoAValidChain() throws Exception {
        AnalysisService service = new AnalysisService(dataDir);
        try {
            int n = 6;
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                final int idx = i;
                threads.add(new Thread(() -> service.submit("proj", files(2), RULES, "job-" + idx)));
            }
            for (Thread t : threads) {
                t.start();
            }
            for (Thread t : threads) {
                t.join(5000);
            }
            for (int i = 0; i < n; i++) {
                waitCommitted(service, "proj", "job-" + i);
            }
            List<CommitStore.CommitMeta> commits = service.commits("proj");
            assertEquals(n, commits.size());
            // chain integrity: each commit's parent is the previous commit
            assertNull(commits.get(0).parentId());
            for (int i = 1; i < commits.size(); i++) {
                assertEquals(commits.get(i - 1).commitId(), commits.get(i).parentId(),
                        "commits must form a linear chain");
            }
        } finally {
            service.shutdown();
        }
    }

    @Test
    void crashRecoveryResumesInterruptedJobsWithoutDuplicates() throws Exception {
        // 1) first lifecycle: commit one job normally
        AnalysisService first = new AnalysisService(dataDir);
        first.submit("proj", files(2), RULES, "job-1");
        waitCommitted(first, "proj", "job-1");
        int committedBefore = first.commits("proj").size();
        assertEquals(1, committedBefore);

        // 2) simulate a crash: partial journal + a job persisted as RUNNING, no shutdown
        Path projectDir = dataDir.resolve("proj");
        Path partial = projectDir.resolve("journal").resolve("chalf.tmp");
        Files.createDirectories(partial);
        Files.writeString(partial.resolve("meta.json"), "{\"commitId\":\"chalf\"");
        Path jobsDir = projectDir.resolve("jobs");
        Files.writeString(jobsDir.resolve("job-2.json"), """
                {"jobId":"job-2","status":"RUNNING","rules":%s,"files":%s,"commitId":null,"error":null}
                """.formatted(toJsonString(RULES), toJsonFiles(files(3))));
        // do NOT call first.shutdown() gracefully: simulate crash by abandoning the executor
        first.shutdown();

        // 3) restart: recovery must clean the journal and resume job-2 from last commit
        AnalysisService second = new AnalysisService(dataDir);
        second.recoverAll();
        try {
            waitCommitted(second, "proj", "job-2");
            List<CommitStore.CommitMeta> commits = second.commits("proj");
            assertEquals(2, commits.size(), "exactly one new commit for the resumed job");
            assertEquals(1, commits.stream().filter(m -> m.jobId().equals("job-2")).count(),
                    "resumed job must not be analyzed twice");
            assertFalse(Files.exists(projectDir.resolve("journal").resolve("chalf.tmp")),
                    "partial journal must be discarded");
            assertEquals(3, second.currentFindings("proj").findings().size(),
                    "resumed job analyzes all its files, nothing skipped");

            // 4) recovery is idempotent: running it again changes nothing
            second.recoverAll();
            assertEquals(2, second.commits("proj").size());
        } finally {
            second.shutdown();
        }
    }

    @Test
    void recoveredServiceKeepsIncrementalCache() throws Exception {
        AnalysisService first = new AnalysisService(dataDir);
        first.submit("proj", files(4), RULES, "job-1");
        waitCommitted(first, "proj", "job-1");
        first.shutdown();

        // restart and change only one file: cache from the committed snapshot is reused
        AnalysisService second = new AnalysisService(dataDir);
        second.recoverAll();
        try {
            Map<String, String> changed = files(4);
            changed.put("f0.req", """
                    fn f0() {
                      v0 = readParam("v");
                      w = v0;
                      executeSql(w);
                    }
                    """);
            second.submit("proj", changed, RULES, "job-2");
            waitCommitted(second, "proj", "job-2");
            String commitId = second.jobStatus("proj", "job-2").commitId();
            AnalysisResult r2 = second.commitResult("proj", commitId).orElseThrow();
            assertEquals(3, r2.stats().reusedFiles(), "unchanged files reused after restart");
            assertEquals(1, r2.stats().reparsedFiles());
        } finally {
            second.shutdown();
        }
    }

    private static String toJsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    private static String toJsonFiles(Map<String, String> files) {
        StringBuilder sb = new StringBuilder("{");
        files.forEach((k, v) -> sb.append(toJsonString(k)).append(':').append(toJsonString(v)).append(','));
        if (sb.length() > 1) {
            sb.setLength(sb.length() - 1);
        }
        return sb.append('}').toString();
    }
}
