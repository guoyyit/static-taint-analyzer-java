package com.github.guoyyit.statictaintanalyzerjava.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.nio.file.Path;

/** Wires the analysis service and runs crash recovery at startup. */
@Configuration
public class ServiceConfig {

    private final AnalysisService service;

    public ServiceConfig(@Value("${taint.data-dir:./taint-data}") String dataDir) {
        this.service = new AnalysisService(Path.of(dataDir));
    }

    @Bean
    public AnalysisService analysisService() {
        return service;
    }

    /** Resumes interrupted jobs from the last committed position. */
    @PostConstruct
    public void recoverOnStartup() {
        service.recover();
    }

    @PreDestroy
    public void shutdown() {
        service.shutdown();
    }
}
