package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DirectoryIncrementalTest {

    private static final String RULES = """
            {
              "sources": [{"id":"src","pattern":"readParam","severity":"HIGH"}],
              "sinks": [{"id":"snk","pattern":"*.execute","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    private static String javaClass(String name) {
        return javaClass(name, true);
    }

    private static String javaClass(String name, boolean sinks) {
        String body = sinks ? "execute(readParam(\"p\"));"
                : "String unused = readParam(\"p\");";
        return """
                package demo;
                public class %s {
                    public String readParam(String k) { return k; }
                    public void execute(String q) { }
                    public void run() { %s }
                }
                """.formatted(name, body);
    }

    @TempDir
    Path dataDir;

    @TempDir
    Path projectRoot;

    private AnalysisService service;

    @BeforeEach
    void setUp() {
        service = new AnalysisService(dataDir);
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    private void write(String relative, String content) throws IOException {
        Path target = projectRoot.resolve(relative);
        Files.createDirectories(target.getParent());
        Files.writeString(target, content, StandardCharsets.UTF_8);
    }

    private String submitAndWait(String jobId) {
        service.submit("proj", java.util.Map.of(), RULES, jobId, List.of(projectRoot.toString()));
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            AnalysisService.JobView view = service.jobStatus("proj", jobId);
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
        fail("job did not commit");
        return null;
    }

    @Test
    void recursivelyDiscoversJavaFiles() throws IOException {
        write("src/main/java/demo/A.java", javaClass("A"));
        write("src/main/java/demo/sub/B.java", javaClass("B"));
        write("notes.txt", "ignore me");
        String commitId = submitAndWait("job-1");
        AnalysisResult result = service.commitResult("proj", commitId).orElseThrow();
        assertEquals(2, result.stats().totalFiles());
        assertEquals(2, result.findings().size());
        assertTrue(result.findings().stream().allMatch(f ->
                f.path().get(0).file().endsWith(".java")));
    }

    @Test
    void additionsDeletionsAndModificationsAreReflectedIncrementally() throws IOException {
        write("demo/A.java", javaClass("A"));
        write("demo/B.java", javaClass("B"));
        String c1 = submitAndWait("job-1");
        AnalysisResult r1 = service.commitResult("proj", c1).orElseThrow();
        assertEquals(2, r1.findings().size());

        write("demo/C.java", javaClass("C"));
        write("demo/A.java", javaClass("A", false));
        String c2 = submitAndWait("job-2");
        AnalysisResult r2 = service.commitResult("proj", c2).orElseThrow();
        assertEquals(1, r2.stats().reusedFiles(), "B unchanged -> reused");
        assertEquals(2, r2.stats().reparsedFiles(), "A modified + C added re-parsed");
        assertTrue(r2.addedFiles().contains("demo/C.java"));
        assertEquals(2, r2.findings().size(), "A no longer sinks; B and C still do");
        java.util.Set<String> sinkFiles2 = r2.findings().stream()
                .map(f -> f.path().get(0).file()).collect(java.util.stream.Collectors.toSet());
        assertEquals(java.util.Set.of("demo/B.java", "demo/C.java"), sinkFiles2);

        Files.delete(projectRoot.resolve("demo/B.java"));
        String c3 = submitAndWait("job-3");
        AnalysisResult r3 = service.commitResult("proj", c3).orElseThrow();
        assertEquals(List.of("demo/B.java"), r3.removedFiles());
        assertEquals(1, r3.findings().size(), "only C remains");
        assertEquals("demo/C.java", r3.findings().get(0).path().get(0).file());
        assertFalse(r3.removedFingerprints().isEmpty(), "deleted finding reported removed");
    }
}
