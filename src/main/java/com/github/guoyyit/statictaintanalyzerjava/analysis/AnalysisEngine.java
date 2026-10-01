package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.JavaFrontend;
import com.github.guoyyit.statictaintanalyzerjava.lang.JavaParseException;
import com.github.guoyyit.statictaintanalyzerjava.lang.ParseFailure;
import com.github.guoyyit.statictaintanalyzerjava.lang.Parser;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Orchestrates parse -> summarize -> global taint analysis for both the legacy
 * DSL and real Java sources.
 *
 * <p>Incremental: per-file summaries are reused only when both the file content
 * hash and the rules hash are unchanged, so rule changes never mix old and new
 * results. Parse failures are isolated per file: one bad file never aborts the
 * project, and each failure carries file name, line and an error code.
 */
public final class AnalysisEngine {

    private final Parser parser = new Parser();
    private final JavaFrontend javaFrontend = new JavaFrontend();
    private final TaintEngine taintEngine = new TaintEngine();

    public AnalysisResult analyze(Map<String, String> files,
                                  AnalysisRules rules,
                                  AnalysisResult previous) {
        return analyze(files, rules, previous, List.of());
    }

    /**
     * Like {@link #analyze(Map, AnalysisRules, AnalysisResult)} but also folds in
     * externally collected per-file failures (e.g. IO failures during a directory scan).
     */
    public AnalysisResult analyze(Map<String, String> files,
                                  AnalysisRules rules,
                                  AnalysisResult previous,
                                  List<ParseFailure> externalFailures) {
        String rulesHash = rules.hash();
        Map<String, String> fileHashes = new TreeMap<>();
        for (Map.Entry<String, String> e : files.entrySet()) {
            fileHashes.put(e.getKey(), TaintEngine.sha256Hex(e.getValue()));
        }

        boolean rulesSame = previous != null && previous.rulesHash().equals(rulesHash);
        Map<String, List<FunctionSummary>> prevByFile = new TreeMap<>();
        Map<String, ParseFailure> prevFailures = new TreeMap<>();
        if (rulesSame && previous != null) {
            for (FunctionSummary s : previous.summaries().values()) {
                prevByFile.computeIfAbsent(s.file(), k -> new ArrayList<>()).add(s);
            }
            for (ParseFailure f : previous.parseFailures()) {
                prevFailures.put(f.file(), f);
            }
        }

        Map<String, FunctionSummary> summaries = new TreeMap<>();
        List<ParseFailure> failures = new ArrayList<>();
        int reused = 0;
        int reparsed = 0;
        int failed = 0;
        for (String file : fileHashes.keySet()) {
            List<FunctionSummary> cached = rulesSame ? prevByFile.get(file) : null;
            boolean hashSame = previous != null
                    && fileHashes.get(file).equals(previous.fileHashes().get(file));
            if (cached != null && hashSame) {
                for (FunctionSummary s : cached) {
                    putSummary(summaries, s);
                }
                reused++;
                continue;
            }
            if (cached == null && hashSame && rulesSame && prevFailures.containsKey(file)) {
                // The file failed identically before; keep the deterministic failure.
                failures.add(prevFailures.get(file));
                failed++;
                continue;
            }
            try {
                List<FunctionSummary> parsed = parseFile(file, files.get(file), rules);
                for (FunctionSummary s : parsed) {
                    putSummary(summaries, s);
                }
                reparsed++;
            } catch (JavaParseException e) {
                failures.add(e.failure());
                failed++;
            }
        }
        for (ParseFailure external : externalFailures) {
            if (!failures.contains(external)) {
                failures.add(external);
                failed++;
            }
        }
        failures.sort((a, b) -> {
            int c = a.file().compareTo(b.file());
            if (c != 0) return c;
            c = Integer.compare(a.line(), b.line());
            if (c != 0) return c;
            return a.code().compareTo(b.code());
        });

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

        List<String> removedFiles = new ArrayList<>();
        if (previous != null) {
            for (String old : previous.fileHashes().keySet()) {
                if (!fileHashes.containsKey(old)) {
                    removedFiles.add(old);
                }
            }
            removedFiles.sort(String::compareTo);
        }

        return new AnalysisResult(rulesHash, fileHashes, summaries, List.copyOf(stamped),
                List.copyOf(removed),
                new AnalysisResult.AnalysisStats(reused, reparsed, failed, removedFiles.size()),
                List.copyOf(failures), List.copyOf(removedFiles));
    }

    private List<FunctionSummary> parseFile(String file, String content, AnalysisRules rules) {
        if (file.endsWith(".java")) {
            return javaFrontend.summarizeFile(file, content);
        }
        List<FunctionSummary> result = new ArrayList<>();
        for (var fn : parser.parse(file, content).functions()) {
            result.add(new Summarizer().summarize(fn, rules));
        }
        return result;
    }

    /**
     * Name collisions resolve to the lexicographically smallest file: deterministic.
     * Only affects the legacy DSL (flat global function names).
     */
    private static void putSummary(Map<String, FunctionSummary> summaries, FunctionSummary s) {
        if (s.ownerClass() != null && !s.ownerClass().isEmpty()) {
            summaries.put(s.functionName(), s);
            return;
        }
        FunctionSummary existing = summaries.get(s.functionName());
        if (existing == null || s.file().compareTo(existing.file()) < 0) {
            summaries.put(s.functionName(), s);
        }
    }
}
