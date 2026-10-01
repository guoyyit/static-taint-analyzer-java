package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DirectoryIncrementalTest {

    private static final String RULES = """
            {
              "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
              "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
              "sanitizers": []
            }
            """;

    @TempDir
    Path dataDir;

    private AnalysisService service;

    private String sourceOf(String cls) {
        return "package p; public class " + cls + " {\n"
                + "  public void m() {\n"
                + "    String x = Source.get();\n"
                + "    Sink.run(x);\n"
                + "  }\n"
                + "}\n";
    }

    private void writeJava(Path root, String name, String content) throws Exception {
        Path pkg = root.resolve("p");
        Files.createDirectories(pkg);
        Files.writeString(pkg.resolve(name), content);
    }

    private String submitAndWait(String jobId) throws Exception {
        String id = service.submit("proj", java.util.Map.of(), RULES, jobId,
                root.toString());
        long deadline = System.currentTimeMillis() + 15_000;
        while (System.currentTimeMillis() < deadline) {
            AnalysisService.JobView view = service.jobStatus("proj", id);
            if (view.status() == AnalysisService.JobStatus.COMMITTED) {
                return view.commitId();
            }
            if (view.status() == AnalysisService.JobStatus.FAILED) {
                fail("job failed: " + view.error());
            }
            try { Thread.sleep(20); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        fail("job did not commit");
        return null;
    }

    private Path root;

    @AfterEach
    void tearDown() {
        if (service != null) {
            service.shutdown();
        }
    }

    @Test
    void addModifyDeleteReflectedIncrementally() throws Exception {
        root = Files.createTempDirectory("java-project");
        service = new AnalysisService(dataDir);

        writeJava(root, "Source.java",
                "package p; public class Source { public static String get() { return \"\"; } }\n");
        writeJava(root, "Sink.java",
                "package p; public class Sink { public static void run(String s) { } }\n");
        writeJava(root, "A.java", sourceOf("A"));
        writeJava(root, "B.java", sourceOf("B"));

        String c1 = submitAndWait("job-1");
        AnalysisResult r1 = service.commitResult("proj", c1).orElseThrow();
        assertEquals(2, r1.findings().size(), "A and B each leak");
        assertEquals(4, r1.fileHashes().size());
        assertEquals(0, r1.stats().reusedFiles());

        // modify A (no leak after sanitize-style change), delete B, add C
        writeJava(root, "A.java",
                "package p; public class A { public void m() { String x = Source.get(); } }\n");
        Files.delete(root.resolve("p").resolve("B.java"));
        writeJava(root, "C.java", sourceOf("C"));

        String c2 = submitAndWait("job-2");
        AnalysisResult r2 = service.commitResult("proj", c2).orElseThrow();
        assertTrue(r2.removedFiles().contains("p/B.java"), "deleted file must be listed as removed: "
                + r2.removedFiles());
        assertTrue(r2.fileHashes().containsKey("p/C.java"));
        assertFalse(r2.fileHashes().containsKey("p/B.java"));
        assertEquals(1, r2.findings().size(), "only C leaks now");
        // Source/Sink unchanged -> reused
        assertEquals(2, r2.stats().reusedFiles(), "unchanged files reused");
        assertEquals(2, r2.stats().reparsedFiles(), "A modified + C added re-parsed");
        assertEquals(1, r2.stats().removedFiles());

        // findings view exposes the same info
        AnalysisService.FindingsView view = service.currentFindings("proj");
        assertEquals(r2.removedFiles(), view.removedFiles());
        assertEquals(2, view.stats().reusedFiles());
    }

    @Test
    void directoryJobRecoversAfterRestart() throws Exception {
        root = Files.createTempDirectory("java-project-recover");
        service = new AnalysisService(dataDir);
        writeJava(root, "Source.java",
                "package p; public class Source { public static String get() { return \"\"; } }\n");
        writeJava(root, "Sink.java",
                "package p; public class Sink { public static void run(String s) { } }\n");
        writeJava(root, "A.java", sourceOf("A"));

        // persist a RUNNING directory job but never run it (simulate crash)
        String dir = root.toString();
        String jobJson = "{\"jobId\":\"job-d\",\"status\":\"RUNNING\",\"rules\":"
                + quoteJson(RULES) + ",\"files\":{},\"directory\":" + quoteJson(dir)
                + ",\"commitId\":null,\"error\":null}";
        java.nio.file.Path jobsDir = dataDir.resolve("proj").resolve("jobs");
        Files.createDirectories(jobsDir);
        Files.writeString(jobsDir.resolve("job-d.json"), jobJson);

        AnalysisService restarted = new AnalysisService(dataDir);
        restarted.recoverAll();
        try {
            long deadline = System.currentTimeMillis() + 15_000;
            while (System.currentTimeMillis() < deadline) {
                AnalysisService.JobView view = restarted.jobStatus("proj", "job-d");
                if (view.status() == AnalysisService.JobStatus.COMMITTED) {
                    break;
                }
                if (view.status() == AnalysisService.JobStatus.FAILED) {
                    fail(view.error());
                }
                Thread.sleep(20);
            }
            assertEquals(1, restarted.commits("proj").size());
            assertEquals(1, restarted.currentFindings("proj").findings().size());
            restarted.recoverAll();
            assertEquals(1, restarted.commits("proj").size(), "no duplicate analysis");
        } finally {
            restarted.shutdown();
        }
    }

    private static String quoteJson(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    @Test
    void unreadableSingleFileIsReportedNotFatal() throws Exception {
        root = Files.createTempDirectory("java-project-io");
        service = new AnalysisService(dataDir);
        writeJava(root, "Good.java",
                "package p; public class Good { public void m(){ int x = 1; } }");
        Path bad = root.resolve("p").resolve("NoRead.java");
        Files.writeString(bad, "package p; public class NoRead {}");
        // make it unreadable where the platform supports it
        boolean denied = bad.toFile().setReadable(false, false);
        try {
            DirectoryScanner.ScanResult scan = DirectoryScanner.scan(root.toString());
            assertTrue(scan.files().containsKey("p/Good.java"));
            if (denied && !Files.isReadable(bad)) {
                assertTrue(scan.failures().stream().anyMatch(
                        f -> f.file().equals("p/NoRead.java") && f.code().equals("IO_ERROR")),
                        "unreadable file must produce IO_ERROR");
            }
        } finally {
            bad.toFile().setReadable(true, true);
        }
    }
}
