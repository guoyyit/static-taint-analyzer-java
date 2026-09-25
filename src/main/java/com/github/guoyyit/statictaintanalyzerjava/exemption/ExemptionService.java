package com.github.guoyyit.statictaintanalyzerjava.exemption;

import com.github.guoyyit.statictaintanalyzerjava.domain.Exemption;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.store.JsonStore;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Manages exemptions. Exemptions are evaluated at query time against the
 * current snapshot and rules, so an expired exemption or a rule change restores
 * detection without any re-analysis. Every mutation is audit-logged.
 */
public final class ExemptionService {

    private final JsonStore json;
    private final Path file;
    private final AuditLog auditLog;
    private final Supplier<Instant> clock;

    public ExemptionService(Path dataDir, JsonStore json, AuditLog auditLog) {
        this(dataDir, json, auditLog, Instant::now);
    }

    /** Test-friendly constructor with an injectable clock. */
    public ExemptionService(Path dataDir, JsonStore json, AuditLog auditLog, Supplier<Instant> clock) {
        this.json = json;
        this.file = dataDir.resolve("exemptions.json");
        this.auditLog = auditLog;
        this.clock = clock;
    }

    public synchronized Exemption create(String fingerprint, String reason, String createdBy,
                                         Instant expiresAt, String currentRuleHash) {
        Exemption exemption = new Exemption(UUID.randomUUID().toString(), fingerprint, reason,
                createdBy, clock.get(), expiresAt, currentRuleHash);
        List<Exemption> all = new ArrayList<>(loadAll());
        all.add(exemption);
        persist(all);
        auditLog.record("EXEMPTION_CREATED", createdBy,
                "id=" + exemption.id() + " fingerprint=" + fingerprint
                        + " expiresAt=" + expiresAt + " reason=" + reason);
        return exemption;
    }

    public synchronized boolean revoke(String id, String actor) {
        List<Exemption> all = new ArrayList<>(loadAll());
        boolean removed = all.removeIf(e -> e.id().equals(id));
        if (removed) {
            persist(all);
            auditLog.record("EXEMPTION_REVOKED", actor, "id=" + id);
        }
        return removed;
    }

    public List<Exemption> list() {
        return loadAll();
    }

    /** True when an active (unexpired, rule-hash-matching) exemption covers the finding. */
    public boolean isExempted(Finding finding) {
        Instant now = clock.get();
        return loadAll().stream().anyMatch(e -> e.appliesTo(finding, now));
    }

    /** Partitions findings into [active, exempted]; order preserved. */
    public List<Finding> filterActive(List<Finding> findings) {
        return findings.stream().filter(f -> !isExempted(f)).toList();
    }

    public List<Finding> filterExempted(List<Finding> findings) {
        return findings.stream().filter(this::isExempted).toList();
    }

    private List<Exemption> loadAll() {
        Optional<Exemption[]> loaded = json.read(file, Exemption[].class);
        return loaded.map(List::of).orElse(List.of());
    }

    private void persist(List<Exemption> all) {
        json.writeAtomic(file, all);
    }
}
