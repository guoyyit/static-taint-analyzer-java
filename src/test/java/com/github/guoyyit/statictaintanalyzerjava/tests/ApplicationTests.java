package com.github.guoyyit.statictaintanalyzerjava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Path;

@SpringBootTest(properties = "taint.data-dir=${java.io.tmpdir}/taint-app-test")
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
