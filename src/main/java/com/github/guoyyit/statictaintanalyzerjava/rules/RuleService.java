package com.github.guoyyit.statictaintanalyzerjava.rules;

import com.github.guoyyit.statictaintanalyzerjava.domain.RuleSet;
import com.github.guoyyit.statictaintanalyzerjava.exemption.AuditLog;
import com.github.guoyyit.statictaintanalyzerjava.store.JsonStore;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the active rule set. Updating rules persists them durably, records an
 * audit event and bumps the rule hash; the next analysis detects the hash
 * change and performs a full recompute, so old-rule and new-rule results are
 * never mixed.
 */
public final class RuleService {

    private final JsonStore json;
    private final Path file;
    private final AuditLog auditLog;
    private final RuleSetLoader loader = new RuleSetLoader();
    private final AtomicReference<RuleSet> active = new AtomicReference<>(RuleSet.empty());

    public RuleService(Path dataDir, JsonStore json, AuditLog auditLog) {
        this.json = json;
        this.file = dataDir.resolve("rules.json");
        this.auditLog = auditLog;
    }

    /** Loads persisted rules at startup. */
    public RuleService init() {
        loader.loadIfExists(file).ifPresent(active::set);
        return this;
    }

    public RuleSet current() {
        return active.get();
    }

    /** Replaces the active rules; returns the new set with its hash. */
    public synchronized RuleSet update(String rulesJson, String actor) {
        RuleSet parsed = loader.parse(rulesJson);
        RuleSet previous = active.get();
        json.writeAtomic(file, parsed);
        active.set(parsed);
        auditLog.record("RULES_UPDATED", actor,
                "from=" + previous.hash() + " to=" + parsed.hash() + " version=" + parsed.version());
        return parsed;
    }
}
