package com.github.guoyyit.statictaintanalyzerjava.api;

import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

@Configuration
public class ServiceConfig {

    @Bean(destroyMethod = "shutdown")
    public AnalysisService analysisService(@Value("${taint.data-dir:./data}") String dataDir) {
        AnalysisService service = new AnalysisService(Path.of(dataDir));
        service.recoverAll();
        return service;
    }
}
