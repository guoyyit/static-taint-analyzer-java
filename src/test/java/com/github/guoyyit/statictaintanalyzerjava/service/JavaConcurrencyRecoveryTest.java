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
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

class JavaConcurrencyRecoveryTest {

    private static final String RULES = """
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    @TempDir
    Path dataDir;

    private Map<String, String> javaFiles(int n) {
        Map<String, String> files = new TreeMap<>();
        files.put("p/Source.java",
                "package p; public class Source { public static String get(){return \"\";} }\n");
        files.put("p/Sink.java",
                "package p; public class Sink { public static void run(String s){} }\n");
        for (int i = 0; i < n; i++) {
            files.put("p/F" + i + ".java", """
                    package p;
                    public class F%d {
                      public void m() {
                        String x = Source.get();
                        Sink.run(x);
                      }
                    }
                    """.formatted(i));
        }
        return files;
    }

    private static void waitCommitted(AnalysisService service, String jobId) {
        long deadline = System.currentTimeMillis() + 15_000;
        while (System.currentTimeMillis() < deadline) {
            AnalysisService.JobView view = service.jobStatus("proj", jobId);
            if (view.status() == AnalysisService.JobStatus.COMMITTED) {
                return;
            }
            if (view.status() == AnalysisService.JobStatus.FAILED) {
                fail("job failed: " + view.error());
            }
            try { Thread.sleep(10); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        fail("job " + jobId + " did not commit");
    }

    @Test
    void concurrentJavaSubmissionsSerializeAndAreConsistent() throws Exception {
        AnalysisService service = new AnalysisService(dataDir);
        try {
            int n = 6;
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                final int idx = i;
                Map<String, String> files = javaFiles(2 + idx);
                threads.add(new Thread(() -> service.submit("proj", files, RULES, "job-" + idx)));
            }
            for (Thread t : threads) {
                t.start();
            }
            for (Thread t : threads) {
                t.join(5000);
            }
            for (int i = 0; i < n; i++) {
                waitCommitted(service, "job-" + i);
            }
            List<CommitStore.CommitMeta> commits = service.commits("proj");
            assertEquals(n, commits.size());
            assertNull(commits.get(0).parentId());
            for (int i = 1; i < commits.size(); i++) {
                assertEquals(commits.get(i - 1).commitId(), commits.get(i).parentId());
            }
            // readers always see a loadable snapshot
            AnalysisService.FindingsView view = service.currentFindings("proj");
            assertNotNull(view.commitId());
            AnalysisResult head = service.commitResult("proj", view.commitId()).orElseThrow();
            assertEquals(head.findings().size(), view.findings().size());
            assertTrue(head.findings().size() >= 2);
        } finally {
            service.shutdown();
        }
    }

    @Test
    void javaJobRecoversAfterCrash() throws Exception {
        AnalysisService first = new AnalysisService(dataDir);
        first.submit("proj", javaFiles(2), RULES, "job-1");
        waitCommitted(first, "job-1");
        first.shutdown();

        // simulate crash with a RUNNING Java job persisted
        Path jobsDir = dataDir.resolve("proj").resolve("jobs");
        Files.createDirectories(jobsDir);
        Map<String, String> three = javaFiles(3);
        StringBuilder filesJson = new StringBuilder("{");
        three.forEach((k, v) -> filesJson.append(quote(k)).append(':').append(quote(v)).append(','));
        filesJson.setLength(filesJson.length() - 1);
        filesJson.append('}');
        Files.writeString(jobsDir.resolve("job-2.json"), """
                {"jobId":"job-2","status":"RUNNING","rules":%s,"files":%s,"directory":null,"commitId":null,"error":null}
                """.formatted(quote(RULES), filesJson));

        AnalysisService second = new AnalysisService(dataDir);
        second.recoverAll();
        try {
            waitCommitted(second, "job-2");
            assertEquals(2, second.commits("proj").size());
            assertEquals(3, second.currentFindings("proj").findings().size(),
                    "recovered Java job analyzes all its files");
            second.recoverAll();
            assertEquals(2, second.commits("proj").size(), "recovery is idempotent");
        } finally {
            second.shutdown();
        }
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
