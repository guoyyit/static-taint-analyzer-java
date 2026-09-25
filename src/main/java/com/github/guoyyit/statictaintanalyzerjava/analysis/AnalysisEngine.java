package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.Ast;
import com.github.guoyyit.statictaintanalyzerjava.lang.Parser;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Orchestrates parse -> summarize -> global taint analysis.
 *
 * Incremental: per-file summaries are reused only when both the file content
 * hash and the rules hash are unchanged, so rule changes never mix old and new
 * results. The global pass runs over the merged summaries, which guarantees no
 * affected path is missed; findings are diffed by fingerprint so unchanged
 * paths keep their UNCHANGED status.
 */
public final class AnalysisEngine {

    private final Parser parser = new Parser();
    private final Summarizer summarizer = new Summarizer();
    private final TaintEngine taintEngine = new TaintEngine();

    public AnalysisResult analyze(Map<String, String> files,
                                  AnalysisRules rules,
                                  AnalysisResult previous) {
        String rulesHash = rules.hash();
        Map<String, String> fileHashes = new TreeMap<>();
        for (Map.Entry<String, String> e : files.entrySet()) {
            fileHashes.put(e.getKey(), TaintEngine.sha256Hex(e.getValue()));
        }

        boolean rulesSame = previous != null && previous.rulesHash().equals(rulesHash);
        Map<String, List<FunctionSummary>> prevByFile = new TreeMap<>();
        if (rulesSame) {
            for (FunctionSummary s : previous.summaries().values()) {
                prevByFile.computeIfAbsent(s.file(), k -> new ArrayList<>()).add(s);
            }
        }

        Map<String, FunctionSummary> summaries = new TreeMap<>();
        int reused = 0;
        int reparsed = 0;
        for (String file : fileHashes.keySet()) {
            List<FunctionSummary> cached = rulesSame ? prevByFile.get(file) : null;
            if (cached != null && fileHashes.get(file).equals(previous.fileHashes().get(file))) {
                for (FunctionSummary s : cached) {
                    putSummary(summaries, s);
                }
                reused++;
            } else {
                Ast.Program program = parser.parse(file, files.get(file));
                for (Ast.FunctionDef fn : program.functions()) {
                    putSummary(summaries, summarizer.summarize(fn, rules));
                }
                reparsed++;
            }
        }

        List<Finding> findings = taintEngine.analyze(summaries, rules);

        Set<String> previousFingerprints = new HashSet<>();
        if (previous != null) {
            for (Finding f : previous.findings()) {
                previousFingerprints.add(f.fingerprint());
            }
        }
        Set<String> currentFingerprints = new HashSet<>();
        List<Finding> stamped = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            currentFingerprints.add(f.fingerprint());
            String status = previousFingerprints.contains(f.fingerprint())
                    ? Finding.STATUS_UNCHANGED : Finding.STATUS_NEW;
            stamped.add(new Finding(f.fingerprint(), f.sourceRuleId(), f.sinkRuleId(),
                    f.severity(), f.path(), status));
        }
        List<String> removed = new ArrayList<>();
        for (String fp : previousFingerprints) {
            if (!currentFingerprints.contains(fp)) {
                removed.add(fp);
            }
        }
        removed.sort(String::compareTo);

        return new AnalysisResult(rulesHash, fileHashes, summaries, List.copyOf(stamped),
                List.copyOf(removed), new AnalysisResult.AnalysisStats(reused, reparsed));
    }

    /** Name collisions resolve to the lexicographically smallest file: deterministic. */
    private static void putSummary(Map<String, FunctionSummary> summaries, FunctionSummary s) {
        FunctionSummary existing = summaries.get(s.functionName());
        if (existing == null || s.file().compareTo(existing.file()) < 0) {
            summaries.put(s.functionName(), s);
        }
    }
}
