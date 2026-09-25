package com.github.guoyyit.statictaintanalyzerjava.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiTest {

    @TempDir
    static Path sharedDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("taint.data-dir", () -> sharedDir.toString());
    }

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + "/api/projects/api-proj" + path;
    }

    @Test
    @SuppressWarnings("unchecked")
    void endToEndAnalysisFlow() {
        String rules = """
                {
                  "sources": [{"id":"user-input","pattern":"readParam","severity":"HIGH"}],
                  "sinks": [{"id":"sql-exec","pattern":"executeSql","severity":"CRITICAL"}],
                  "sanitizers": []
                }
                """;
        Map<String, Object> submit = Map.of(
                "files", Map.of("a.req", """
                        fn a() {
                          x = readParam("x");
                          executeSql(x);
                        }
                        """),
                "rules", rules,
                "jobId", "api-job-1");
        Map<String, String> submitResp = rest.postForObject(url("/analyses"), submit, Map.class);
        assertEquals("api-job-1", submitResp.get("jobId"));

        // poll job status until committed
        Map<String, Object> status = null;
        for (int i = 0; i < 200; i++) {
            status = rest.getForObject(url("/analyses/api-job-1"), Map.class);
            if ("COMMITTED".equals(status.get("status"))) {
                break;
            }
            try {
                Thread.sleep(25);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        assertNotNull(status);
        assertEquals("COMMITTED", status.get("status"));
        assertNotNull(status.get("commitId"));

        Map<String, Object> findings = rest.getForObject(url("/findings"), Map.class);
        List<Map<String, Object>> list = (List<Map<String, Object>>) findings.get("findings");
        assertEquals(1, list.size());
        assertEquals("user-input", list.get(0).get("sourceRuleId"));
        assertEquals("sql-exec", list.get(0).get("sinkRuleId"));
        String fingerprint = (String) list.get(0).get("fingerprint");
        assertNotNull(fingerprint);

        // exempt via API and verify suppression
        Map<String, Object> exemption = rest.postForObject(url("/exemptions"),
                Map.of("fingerprint", fingerprint, "reason", "test", "createdBy", "api"), Map.class);
        assertNotNull(exemption.get("id"));
        Map<String, Object> after = rest.getForObject(url("/findings"), Map.class);
        List<String> suppressed = (List<String>) after.get("suppressedFingerprints");
        assertTrue(suppressed.contains(fingerprint));

        List<Map<String, Object>> audit = rest.getForObject(url("/audit"), List.class);
        assertFalse(audit.isEmpty());
    }
}
