package com.github.guoyyit.statictaintanalyzerjava.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ApiIntegrationTest {

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

    private static final String SOURCE = """
            package demo;
            public class Dao {
                public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) {
                    stmt.executeQuery(req.getParameter("q"));
                }
            }
            """;

    @TempDir
    static Path dataDir;
    @TempDir
    Path sourceDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("taint.data-dir", () -> dataDir.toString());
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper mapper;

    @BeforeEach
    void writeSource() throws Exception {
        Files.createDirectories(sourceDir.resolve("demo"));
        Files.writeString(sourceDir.resolve("demo/Dao.java"), SOURCE);
    }

    @Test
    void fullWorkflowOverHttp() throws Exception {
        // Configure rules.
        mvc.perform(put("/api/rules").contentType(MediaType.APPLICATION_JSON).content(RULES))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hash").isNotEmpty());

        // Submit analysis and wait for completion.
        MvcResult submit = mvc.perform(post("/api/analysis/jobs")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sourceDir\": \"" + sourceDir + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String jobId = mapper.readTree(submit.getResponse().getContentAsString()).get("jobId").asText();
        mvc.perform(post("/api/analysis/jobs/" + jobId + "/await"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COMMITTED"));

        // Query findings: exactly one HIGH finding.
        MvcResult findings = mvc.perform(get("/api/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].risk").value("HIGH"))
                .andReturn();
        String fingerprint = mapper.readTree(findings.getResponse().getContentAsString())
                .get(0).get("fingerprint").asText();

        // Exempt it; it disappears from the default query but stays auditable.
        mvc.perform(post("/api/exemptions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fingerprint\": \"" + fingerprint + "\", \"reason\": \"accepted\", "
                                + "\"createdBy\": \"tester\", \"expiresAt\": null}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/findings")).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/findings").param("includeExempted", "true"))
                .andExpect(jsonPath("$.length()").value(1));

        // Audit trail contains the exemption and the commit.
        MvcResult audit = mvc.perform(get("/api/audit")).andExpect(status().isOk()).andReturn();
        JsonNode events = mapper.readTree(audit.getResponse().getContentAsString());
        assertTrue(events.size() >= 3, "audit trail must record rule update, commit, exemption");
        String all = events.toString();
        assertTrue(all.contains("EXEMPTION_CREATED"));
        assertTrue(all.contains("ANALYSIS_COMMITTED"));
        assertTrue(all.contains("RULES_UPDATED"));
        assertEquals(1, mapper.readTree(
                mvc.perform(get("/api/snapshots/current")).andReturn().getResponse()
                        .getContentAsString()).get("version").asInt());
    }
}
