package com.github.guoyyit.statictaintanalyzerjava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;

import static org.junit.jupiter.api.Assertions.*;

class JobStateCompatTest {

    @Test
    @SuppressWarnings("unchecked")
    void oldJobJsonWithoutDirectoryDeserializes() throws Exception {
        Class<?> clazz = Class.forName(
                "com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService$JobState");
        ObjectMapper mapper = new ObjectMapper();
        String old = """
                {"jobId":"j1","status":"COMMITTED","rules":"{}",
                 "files":{"a.req":"x"},"commitId":"c1","error":null}
                """;
        Object state = mapper.readValue(old, clazz);
        RecordComponent dir = null;
        for (RecordComponent rc : clazz.getRecordComponents()) {
            if (rc.getName().equals("directory")) {
                dir = rc;
            }
        }
        assertNotNull(dir, "JobState must keep a directory component");
        assertNull(dir.getAccessor().invoke(state));
        Object files = clazz.getMethod("files").invoke(state);
        assertEquals(1, ((java.util.Map<String, String>) files).size());
    }
}
