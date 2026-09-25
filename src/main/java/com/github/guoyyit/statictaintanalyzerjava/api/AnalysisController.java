package com.github.guoyyit.statictaintanalyzerjava.api;

import com.github.guoyyit.statictaintanalyzerjava.domain.AnalysisSnapshot;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.domain.RiskLevel;
import com.github.guoyyit.statictaintanalyzerjava.service.AnalysisService;
import com.github.guoyyit.statictaintanalyzerjava.store.JobRecord;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Analysis submission and result queries. */
@RestController
@RequestMapping("/api")
public class AnalysisController {

    private final AnalysisService service;

    public AnalysisController(AnalysisService service) {
        this.service = service;
    }

    public record SubmitRequest(String sourceDir) {
    }

    public record SubmitResponse(String jobId) {
    }

    @PostMapping("/analysis/jobs")
    public SubmitResponse submit(@RequestBody SubmitRequest request) {
        return new SubmitResponse(service.submit(request.sourceDir()));
    }

    @PostMapping("/analysis/jobs/{jobId}/await")
    public ResponseEntity<JobRecord> await(@PathVariable String jobId) {
        service.await(jobId);
        return service.job(jobId).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/analysis/jobs/{jobId}")
    public ResponseEntity<JobRecord> job(@PathVariable String jobId) {
        return service.job(jobId).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/analysis/jobs")
    public List<JobRecord> jobs() {
        return service.jobs();
    }

    @GetMapping("/snapshots/current")
    public AnalysisSnapshot currentSnapshot() {
        return service.currentSnapshot();
    }

    @GetMapping("/findings")
    public List<Finding> findings(@RequestParam(required = false) String minRisk,
                                  @RequestParam(defaultValue = "false") boolean includeExempted) {
        RiskLevel risk = minRisk == null ? null : RiskLevel.fromString(minRisk);
        return service.queryFindings(risk, includeExempted);
    }

    @GetMapping("/findings/{fingerprint}")
    public ResponseEntity<Finding> finding(@PathVariable String fingerprint) {
        return service.finding(fingerprint).map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/baseline")
    public Map<String, String> markBaseline(@RequestParam(defaultValue = "api") String actor) {
        service.markBaseline(actor);
        return Map.of("status", "ok");
    }

    @GetMapping("/findings/new-since-baseline")
    public List<Finding> newSinceBaseline() {
        return service.findingsNewSinceBaseline();
    }
}
