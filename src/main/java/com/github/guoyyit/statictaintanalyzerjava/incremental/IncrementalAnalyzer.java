package com.github.guoyyit.statictaintanalyzerjava.incremental;

import com.fasterxml.jackson.core.type.TypeReference;
import com.github.guoyyit.statictaintanalyzerjava.analysis.TaintEngine;
import com.github.guoyyit.statictaintanalyzerjava.analysis.model.MethodSummary;
import com.github.guoyyit.statictaintanalyzerjava.analysis.model.ProgramModel;
import com.github.guoyyit.statictaintanalyzerjava.domain.AnalysisSnapshot;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.domain.RuleSet;
import com.github.guoyyit.statictaintanalyzerjava.store.JsonStore;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Incremental analysis driver. Computes the set of methods affected by file
 * changes (changed files' methods + transitive callers + readers of fields the
 * changed methods write + their transitive callers), re-analyzes only those,
 * and diffs findings against the last committed snapshot. Unchanged findings
 * keep their identity (fingerprint, firstSeen); removed findings are reported
 * but never carried into the new snapshot.
 */
public final class IncrementalAnalyzer {

    /** Per-fingerprint diff status of a run. */
    public enum Status {NEW, UNCHANGED, REMOVED}

    public record Outcome(AnalysisSnapshot snapshot, Map<String, Status> diff) {
    }

    private final JsonStore json;

    public IncrementalAnalyzer(JsonStore json) {
        this.json = json;
    }

    /**
     * @param model         program model built from the current sources
     * @param fileHashes    current path -> content hash
     * @param rules         active rule set
     * @param prior         last committed snapshot (empty for the first run)
     * @param priorFindings findings of the last committed snapshot
     * @param newVersion    version to stamp on the new snapshot
     */
    public Outcome analyze(ProgramModel model, Map<String, String> fileHashes, RuleSet rules,
                           AnalysisSnapshot prior, List<Finding> priorFindings, long newVersion) {
        boolean fullRecompute = prior.version() == 0 || !prior.ruleHash().equals(rules.hash());

        Set<String> affected;
        List<Finding> reusablePrior;
        if (fullRecompute) {
            affected = new TreeSet<>();
            model.methods().forEach(m -> affected.add(m.signature()));
            reusablePrior = List.of();
        } else {
            Set<String> changedFiles = changedFiles(prior.fileHashes(), fileHashes);
            affected = affectedMethods(model, changedFiles);
            // Findings of deleted methods must not be reused; everything else can be.
            Set<String> liveMethods = new TreeSet<>();
            model.methods().forEach(m -> liveMethods.add(m.signature()));
            reusablePrior = priorFindings.stream()
                    .filter(f -> liveMethods.contains(f.sinkMethodSignature()))
                    .toList();
        }

        Map<String, MethodSummary> priorSummaries = deserializeSummaries(prior.methodSummaries());
        TaintEngine.Result result = new TaintEngine(model, rules)
                .analyze(affected, priorSummaries, reusablePrior, newVersion);

        // Diff and carry over firstSeen for unchanged findings.
        Map<String, Finding> priorByFp = new LinkedHashMap<>();
        priorFindings.forEach(f -> priorByFp.put(f.fingerprint(), f));
        Map<String, Status> diff = new TreeMap<>();
        List<Finding> merged = new ArrayList<>();
        for (Finding f : result.findings()) {
            Finding old = priorByFp.remove(f.fingerprint());
            if (old == null) {
                diff.put(f.fingerprint(), Status.NEW);
                merged.add(f.withSeenVersions(newVersion, newVersion));
            } else {
                diff.put(f.fingerprint(), Status.UNCHANGED);
                merged.add(f.withSeenVersions(old.firstSeenVersion(), newVersion));
            }
        }
        priorByFp.forEach((fp, f) -> diff.put(fp, Status.REMOVED));

        List<Finding> sorted = Finding.dedupAndSort(merged);
        AnalysisSnapshot snapshot = new AnalysisSnapshot(newVersion, Instant.now(), rules.hash(),
                sorted, fileHashes, serializeSummaries(result.summaries()), indexByMethod(sorted));
        return new Outcome(snapshot, diff);
    }

    /** Files created, deleted or content-changed between two hash maps. */
    public static Set<String> changedFiles(Map<String, String> prior, Map<String, String> current) {
        Set<String> changed = new TreeSet<>();
        current.forEach((path, hash) -> {
            if (!hash.equals(prior.get(path))) {
                changed.add(path);
            }
        });
        prior.forEach((path, hash) -> {
            if (!current.containsKey(path)) {
                changed.add(path);
            }
        });
        return changed;
    }

    /**
     * Affected-method closure: methods in changed files, readers of fields those
     * methods write, and the transitive callers of all of these.
     */
    public static Set<String> affectedMethods(ProgramModel model, Set<String> changedFiles) {
        Set<String> affected = new TreeSet<>();
        Deque<String> worklist = new ArrayDeque<>();
        for (String file : changedFiles) {
            for (String sig : model.methodsInFile(file)) {
                if (affected.add(sig)) {
                    worklist.add(sig);
                }
            }
        }
        // Field impact: readers of fields written by changed methods are affected too.
        Set<String> fieldsToCheck = new TreeSet<>();
        for (String sig : new TreeSet<>(affected)) {
            fieldsToCheck.addAll(fieldsWrittenBy(model, sig));
        }
        for (String field : fieldsToCheck) {
            for (String reader : model.readersOfField(field)) {
                if (affected.add(reader)) {
                    worklist.add(reader);
                }
            }
        }
        // Transitive callers.
        while (!worklist.isEmpty()) {
            String sig = worklist.poll();
            for (String caller : model.callersOf(sig)) {
                if (affected.add(caller)) {
                    worklist.add(caller);
                }
            }
        }
        return affected;
    }

    private static Set<String> fieldsWrittenBy(ProgramModel model, String signature) {
        Set<String> fields = new TreeSet<>();
        for (String field : model.allFieldKeys()) {
            if (model.writersOfField(field).contains(signature)) {
                fields.add(field);
            }
        }
        return fields;
    }

    private Map<String, MethodSummary> deserializeSummaries(Map<String, String> serialized) {
        Map<String, MethodSummary> out = new TreeMap<>();
        serialized.forEach((sig, s) -> {
            try {
                out.put(sig, json.mapper().readValue(s, MethodSummary.class));
            } catch (Exception e) {
                throw new IllegalStateException("corrupt summary for " + sig, e);
            }
        });
        return out;
    }

    private Map<String, String> serializeSummaries(Map<String, MethodSummary> summaries) {
        Map<String, String> out = new TreeMap<>();
        summaries.forEach((sig, s) -> {
            try {
                out.put(sig, json.mapper().writeValueAsString(s));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        return out;
    }

    private static Map<String, List<String>> indexByMethod(List<Finding> findings) {
        Map<String, List<String>> index = new TreeMap<>();
        for (Finding f : findings) {
            index.computeIfAbsent(f.sinkMethodSignature(), k -> new ArrayList<>()).add(f.fingerprint());
        }
        return index;
    }
}
