package com.github.guoyyit.statictaintanalyzerjava.api;

import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import com.github.guoyyit.statictaintanalyzerjava.store.AuditLog;
import com.github.guoyyit.statictaintanalyzerjava.store.CommitStore;
import com.github.guoyyit.statictaintanalyzerjava.store.ExemptionStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * REST API: submit analyses, query committed findings, manage exemptions and audit.
 */
@RestController
@RequestMapping("/api/projects/{project}")
public class AnalysisController {

    private final AnalysisService service;

    public AnalysisController(AnalysisService service) {
        this.service = service;
    }

    public record SubmitRequest(Map<String, String> files, String rules, String jobId,
                                java.util.List<String> directories) {
    }

    public record SubmitResponse(String jobId) {
    }

    @PostMapping("/analyses")
    public SubmitResponse submit(@PathVariable String project, @RequestBody SubmitRequest req) {
        String jobId = service.submit(project, req.files(), req.rules(), req.jobId(),
                req.directories() == null ? java.util.List.of() : req.directories());
        return new SubmitResponse(jobId);
    }

    @GetMapping("/analyses/{jobId}")
    public ResponseEntity<AnalysisService.JobView> jobStatus(@PathVariable String project,
                                                             @PathVariable String jobId) {
        AnalysisService.JobView view = service.jobStatus(project, jobId);
        if (view.status() == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(view);
    }

    @GetMapping("/findings")
    public AnalysisService.FindingsView findings(@PathVariable String project) {
        return service.currentFindings(project);
    }

    @GetMapping("/commits")
    public List<CommitStore.CommitMeta> commits(@PathVariable String project) {
        return service.commits(project);
    }

    @GetMapping("/commits/{commitId}/findings")
    public ResponseEntity<AnalysisService.FindingsView> commitFindings(@PathVariable String project,
                                                                       @PathVariable String commitId) {
        AnalysisService.FindingsView view = service.commitFindings(project, commitId);
        if (view == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(view);
    }

    public record ExemptionRequest(String fingerprint, String reason, String createdBy, String expiresAt) {
    }

    @PostMapping("/exemptions")
    public ResponseEntity<ExemptionStore.Exemption> exempt(@PathVariable String project,
                                                           @RequestBody ExemptionRequest req) {
        Instant expiresAt = req.expiresAt() == null || req.expiresAt().isBlank()
                ? null : Instant.parse(req.expiresAt());
        String createdBy = req.createdBy() == null ? "anonymous" : req.createdBy();
        try {
            return ResponseEntity.ok(service.exempt(project, req.fingerprint(), req.reason(), createdBy, expiresAt));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
    }

    @GetMapping("/exemptions")
    public List<ExemptionStore.Exemption> exemptions(@PathVariable String project) {
        return service.exemptions(project);
    }

    @DeleteMapping("/exemptions/{id}")
    public ResponseEntity<ExemptionStore.Exemption> revoke(@PathVariable String project,
                                                           @PathVariable String id,
                                                           @RequestParam(defaultValue = "anonymous") String actor) {
        return service.revokeExemption(project, id, actor)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/audit")
    public List<AuditLog.AuditEvent> audit(@PathVariable String project) {
        return service.audit(project);
    }
}
