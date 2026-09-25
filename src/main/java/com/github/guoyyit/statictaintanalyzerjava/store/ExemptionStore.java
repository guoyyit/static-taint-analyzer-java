package com.github.guoyyit.statictaintanalyzerjava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Append-audited exemption store. An exemption suppresses a finding only while
 * it is not revoked, not expired, and bound to the current rules hash; when the
 * rules change or the exemption expires, detection resumes automatically.
 * Every mutation is written atomically and recorded in the audit log.
 */
public final class ExemptionStore {

    public record Exemption(String id, String fingerprint, String rulesHash,
                            String reason, String createdBy, Instant createdAt,
                            Instant expiresAt, boolean revoked) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private final Path storeFile;
    private final AuditLog auditLog;

    public ExemptionStore(Path projectDir) {
        this.storeFile = projectDir.resolve("exemptions.json");
        this.auditLog = new AuditLog(projectDir);
    }

    public AuditLog auditLog() {
        return auditLog;
    }

    public synchronized Exemption create(String fingerprint, String rulesHash, String reason,
                                         String createdBy, Instant expiresAt) {
        List<Exemption> all = new ArrayList<>(loadAll());
        String id = "ex-" + com.github.guoyyit.statictaintanalyzerjava.analysis.TaintEngine
                .sha256Hex(fingerprint + "|" + rulesHash + "|" + all.size() + "|" + Instant.now())
                .substring(0, 12);
        Exemption exemption = new Exemption(id, fingerprint, rulesHash, reason, createdBy,
                Instant.now(), expiresAt, false);
        all.add(exemption);
        saveAll(all);
        auditLog.append(createdBy, "EXEMPTION_CREATED",
                "id=" + id + " fingerprint=" + fingerprint + " expiresAt=" + expiresAt + " reason=" + reason);
        return exemption;
    }

    public synchronized Optional<Exemption> revoke(String id, String actor) {
        List<Exemption> all = new ArrayList<>(loadAll());
        for (int i = 0; i < all.size(); i++) {
            Exemption e = all.get(i);
            if (e.id().equals(id) && !e.revoked()) {
                Exemption revoked = new Exemption(e.id(), e.fingerprint(), e.rulesHash(), e.reason(),
                        e.createdBy(), e.createdAt(), e.expiresAt(), true);
                all.set(i, revoked);
                saveAll(all);
                auditLog.append(actor, "EXEMPTION_REVOKED", "id=" + id);
                return Optional.of(revoked);
            }
        }
        return Optional.empty();
    }

    public synchronized List<Exemption> list() {
        return loadAll();
    }

    /** Active exemptions applicable to the given rules hash at the given time. */
    public List<Exemption> activeFor(String rulesHash, Instant now) {
        List<Exemption> active = new ArrayList<>();
        for (Exemption e : loadAll()) {
            if (e.revoked()) {
                continue;
            }
            if (!e.rulesHash().equals(rulesHash)) {
                continue;
            }
            if (e.expiresAt() != null && !e.expiresAt().isAfter(now)) {
                continue;
            }
            active.add(e);
        }
        return active;
    }

    private List<Exemption> loadAll() {
        if (!Files.exists(storeFile)) {
            return List.of();
        }
        try {
            return MAPPER.readValue(storeFile.toFile(), new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read exemptions", e);
        }
    }

    private void saveAll(List<Exemption> all) {
        try {
            Files.createDirectories(storeFile.getParent());
            Path tmp = storeFile.resolveSibling("exemptions.json.tmp");
            Files.writeString(tmp, MAPPER.writeValueAsString(all));
            Files.move(tmp, storeFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to save exemptions", e);
        }
    }
}
