package com.github.guoyyit.statictaintanalyzerjava.api;

import com.github.guoyyit.statictaintanalyzerjava.domain.RuleSet;
import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Declarative rule management. */
@RestController
@RequestMapping("/api/rules")
public class RuleController {

    private final AnalysisService service;

    public RuleController(AnalysisService service) {
        this.service = service;
    }

    @GetMapping
    public RuleSet current() {
        return service.ruleService().current();
    }

    /** Replaces the active rules; the next analysis performs a full recompute. */
    @PutMapping
    public RuleSet update(@RequestBody String rulesJson,
                          @RequestParam(defaultValue = "api") String actor) {
        return service.ruleService().update(rulesJson, actor);
    }
}
