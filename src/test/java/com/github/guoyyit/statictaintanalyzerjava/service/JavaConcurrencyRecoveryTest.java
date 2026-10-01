package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

class JavaConcurrencyRecoveryTest {

    private static final String RULES = """
            {
              "sources": [{"id":"src","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"snk","pattern":"*.execute","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    private static String javaFile(String index) {
        return """
                package demo;
                public class Cls%s {
                    public String readParam(String k) { return k; }
                    public void execute(String q) { }
                    public void run() { execute(readParam("p")); }
                }
                """.formatted(index);
    }

    private static Map<String, String> files(int n) {
        Map<String, String> files = new TreeMap<>();
        for (int i = 0; i < n; i++) {
            files.put("demo/Cls" + i + ".java", javaFile(String.valueOf(i)));
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
        fail("job " + jobId + " did not commit");
    }

    @TempDir
    Path dataDir;

    @Test
    void concurrentJavaSubmissionsSerializeAndStayConsistent() throws Exception {
        AnalysisService service = new AnalysisService(dataDir);
        try {
            int n = 5;
            final Map<String, String> snapshot = files(6);
            Thread[] threads = new Thread[n];
            for (int i = 0; i < n; i++) {
                final int idx = i;
                threads[i] = new Thread(() -> service.submit("proj", snapshot, RULES, "job-" + idx));
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
            var commits = service.commits("proj");
            assertEquals(n, commits.size());
            for (int i = 1; i < commits.size(); i++) {
                assertEquals(commits.get(i - 1).commitId(), commits.get(i).parentId());
            }
            AnalysisService.FindingsView head = service.currentFindings("proj");
            // each job submits a complete snapshot; the chain's head is the last one
            assertEquals(snapshot.size(), head.findings().size());
            assertTrue(head.parseFailures().isEmpty());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void crashRecoveryCompletesInterruptedJavaJobWithoutDuplicates() throws Exception {
        AnalysisService first = new AnalysisService(dataDir);
        first.submit("proj", files(2), RULES, "job-1");
        waitCommitted(first, "proj", "job-1");
        first.shutdown();

        Path projectDir = dataDir.resolve("proj");
        Path jobsDir = projectDir.resolve("jobs");
        Files.createDirectories(jobsDir);
        Map<String, Object> jobState = new TreeMap<>();
        jobState.put("jobId", "job-2");
        jobState.put("status", "RUNNING");
        jobState.put("rules", RULES);
        jobState.put("files", files(3));
        jobState.put("commitId", null);
        jobState.put("error", null);
        new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValue(jobsDir.resolve("job-2.json").toFile(), jobState);

        AnalysisService second = new AnalysisService(dataDir);
        second.recoverAll();
        try {
            waitCommitted(second, "proj", "job-2");
            assertEquals(2, second.commits("proj").size());
            AnalysisService.FindingsView view = second.currentFindings("proj");
            assertEquals(3, view.findings().size(), "all 3 Java files analyzed after recovery");
            assertTrue(view.parseFailures().isEmpty());
            second.recoverAll();
            assertEquals(2, second.commits("proj").size(), "recovery is idempotent");
        } finally {
            second.shutdown();
        }
    }

    @Test
    void incrementalJavaCacheSurvivesRestart() throws Exception {
        AnalysisService first = new AnalysisService(dataDir);
        first.submit("proj", files(3), RULES, "job-1");
        waitCommitted(first, "proj", "job-1");
        first.shutdown();

        AnalysisService second = new AnalysisService(dataDir);
        second.recoverAll();
        try {
            Map<String, String> changed = files(3);
            changed.put("demo/Cls0.java", javaFile("0").replace("readParam(\"p\")",
                    "readParam(\"changed\")"));
            second.submit("proj", changed, RULES, "job-2");
            waitCommitted(second, "proj", "job-2");
            String commitId = second.jobStatus("proj", "job-2").commitId();
            AnalysisResult result = second.commitResult("proj", commitId).orElseThrow();
            assertEquals(2, result.stats().reusedFiles(), "unchanged Java files reused after restart");
            assertEquals(1, result.stats().reparsedFiles());
        } finally {
            second.shutdown();
        }
    }

}
