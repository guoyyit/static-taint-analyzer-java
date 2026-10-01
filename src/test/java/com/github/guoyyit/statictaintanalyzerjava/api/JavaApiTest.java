package com.github.guoyyit.statictaintanalyzerjava.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JavaApiTest {

    @TempDir
    static Path dataDir;

    @TempDir
    Path projectDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("taint.data-dir", () -> dataDir.toString());
    }

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + "/api/projects/java-api" + path;
    }

    private void write(String rel, String content) throws Exception {
        Path file = projectDir.resolve(rel);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    @Test
    @SuppressWarnings("unchecked")
    void submitJavaDirectoryAndReadFindings() throws Exception {
        write("p/Source.java", "package p; public class Source { static String get(){return \"\";} }");
        write("p/Sink.java", "package p; public class Sink { static void run(String s){} }");
        write("p/Main.java", """
                package p;
                public class Main {
                  public void m() {
                    String x = Source.get();
                    Sink.run(x);
                  }
                }
                """);
        write("p/Broken.java", "package p; public class Broken { void oops( { }");

        String rules = """
                {
                  "sources": [{"id":"in","pattern":"p.Source#get","severity":"HIGH"}],
                  "sinks": [{"id":"out","pattern":"p.Sink#run","severity":"CRITICAL"}],
                  "sanitizers": []
                }
                """;
        Map<String, Object> submit = Map.of(
                "rules", rules,
                "jobId", "j1",
                "directory", projectDir.toString());
        Map<String, String> resp = rest.postForObject(url("/analyses"), submit, Map.class);
        assertEquals("j1", resp.get("jobId"));

        Map<String, Object> status = null;
        for (int i = 0; i < 300; i++) {
            status = rest.getForObject(url("/analyses/j1"), Map.class);
            if ("COMMITTED".equals(status.get("status"))) {
                break;
            }
            if ("FAILED".equals(status.get("status"))) {
                fail("job failed: " + status.get("error"));
            }
            Thread.sleep(25);
        }
        assertEquals("COMMITTED", status.get("status"));

        Map<String, Object> findings = rest.getForObject(url("/findings"), Map.class);
        List<Map<String, Object>> list = (List<Map<String, Object>>) findings.get("findings");
        assertEquals(1, list.size());
        List<Map<String, Object>> failures = (List<Map<String, Object>>) findings.get("parseFailures");
        assertEquals(1, failures.size());
        assertEquals("p/Broken.java", failures.get(0).get("file"));
        assertEquals("SYNTAX_ERROR", failures.get(0).get("code"));
        assertNotNull(failures.get(0).get("line"));

        List<Map<String, Object>> path = (List<Map<String, Object>>) list.get(0).get("path");
        for (Map<String, Object> step : path) {
            assertNotNull(step.get("file"));
            assertNotNull(step.get("className"));
            assertNotNull(step.get("method"));
            assertNotNull(step.get("line"));
        }
    }
}
