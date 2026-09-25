package com.github.guoyyit.statictaintanalyzerjava.api;

import com.github.guoyyit.statictaintanalyzerjava.domain.AuditEvent;
import com.github.guoyyit.statictaintanalyzerjava.domain.Exemption;
import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/** Exemption management and audit trail. */
@RestController
@RequestMapping("/api")
public class ExemptionController {

    private final AnalysisService service;

    public ExemptionController(AnalysisService service) {
        this.service = service;
    }

    public record ExemptionRequest(String fingerprint, String reason, String createdBy,
                                   Instant expiresAt) {
    }

    @PostMapping("/exemptions")
    public Exemption create(@RequestBody ExemptionRequest request) {
        return service.exemptionService().create(request.fingerprint(), request.reason(),
                request.createdBy() == null ? "api" : request.createdBy(), request.expiresAt(),
                service.ruleService().current().hash());
    }

    @GetMapping("/exemptions")
    public List<Exemption> list() {
        return service.exemptionService().list();
    }

    @DeleteMapping("/exemptions/{id}")
    public ResponseEntity<Void> revoke(@PathVariable String id,
                                       @RequestParam(defaultValue = "api") String actor) {
        return service.exemptionService().revoke(id, actor)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @GetMapping("/audit")
    public List<AuditEvent> audit() {
        return service.auditLog().events();
    }
}
