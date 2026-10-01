package com.github.guoyyit.statictaintanalyzerjava.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JavaDirectoryApiTest {

    @TempDir
    static Path sharedDataDir;

    @TempDir
    Path projectDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("taint.data-dir", () -> sharedDataDir.toString());
    }

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + "/api/projects/java-dir" + path;
    }

    private void write(String relative, String content) throws Exception {
        Path target = projectDir.resolve(relative);
        Files.createDirectories(target.getParent());
        Files.writeString(target, content, StandardCharsets.UTF_8);
    }

    @Test
    @SuppressWarnings("unchecked")
    void submitDirectoryViaExistingEndpointAndObserveResultsAndFailures() throws Exception {
        write("src/com/acme/Service.java", """
                package com.acme;
                public class Service {
                    public String readParam(String k) { return k; }
                    public void execute(String q) { }
                    public void handle() { execute(readParam("name")); }
                }
                """);
        write("src/com/acme/Broken.java", "package com.acme; public class Broken { void m(){ if( } }");

        String rules = """
                {"sources":[{"id":"src","pattern":"readParam","severity":"HIGH"}],
                 "sinks":[{"id":"snk","pattern":"*.execute","severity":"CRITICAL"}],
                 "sanitizers":[]}""";
        Map<String, Object> body = Map.of(
                "files", Map.of(),
                "rules", rules,
                "jobId", "dir-job-1",
                "directories", List.of(projectDir.resolve("src").toString()));
        Map<String, String> resp = rest.postForObject(url("/analyses"), body, Map.class);
        assertEquals("dir-job-1", resp.get("jobId"));

        Map<String, Object> status = null;
        for (int i = 0; i < 200; i++) {
            status = rest.getForObject(url("/analyses/dir-job-1"), Map.class);
            if ("COMMITTED".equals(status.get("status"))) {
                break;
            }
            Thread.sleep(25);
        }
        assertEquals("COMMITTED", status.get("status"));

        Map<String, Object> findings = rest.getForObject(url("/findings"), Map.class);
        List<Map<String, Object>> list = (List<Map<String, Object>>) findings.get("findings");
        assertEquals(1, list.size());
        List<Map<String, Object>> steps = (List<Map<String, Object>>) list.get(0).get("path");
        assertTrue(steps.stream().anyMatch(s -> "com.acme.Service".equals(s.get("className"))));
        assertTrue(steps.stream().anyMatch(s -> s.get("file").toString().endsWith("Service.java")));

        List<Map<String, Object>> failures = (List<Map<String, Object>>) findings.get("parseFailures");
        assertEquals(1, failures.size());
        assertEquals("SYNTAX", failures.get(0).get("reason"));
        assertNotNull(failures.get(0).get("line"));
        assertTrue(failures.get(0).get("file").toString().endsWith("Broken.java"));
    }
}
