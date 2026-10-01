package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;
import com.github.guoyyit.statictaintanalyzerjava.rules.Severity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Deterministic bounded taint propagation over the global flow graph.
 *
 * <p>Works for both the legacy DSL (flat function names) and real Java
 * (methods addressed as {@code qualified.Class#method} via a {@link ClassModel}).
 * Propagation is a least-fixpoint union of source labels over a finite graph,
 * so loops, recursion and aliases terminate with order-independent results.
 * Each (source, sink) pair yields one shortest path found by BFS with sorted
 * neighbors, which makes findings stable and reproducible.
 */
public final class TaintEngine {

    /** Max steps of a reconstructed path; keeps results bounded on recursion. */
    public static final int MAX_PATH_LENGTH = 64;

    /** Synthetic function-like scope shared by all static fields. */
    public static final String STATIC_FN = JavaSummarizer.STATIC_SCOPE;

    /** A taint label: where the untrusted value entered the program. */
    public record SourceLabel(String ruleId, String file, int line) implements Comparable<SourceLabel> {
        @Override
        public int compareTo(SourceLabel o) {
            int c = ruleId.compareTo(o.ruleId);
            if (c != 0) return c;
            c = file.compareTo(o.file);
            return c != 0 ? c : Integer.compare(line, o.line);
        }

        @Override
        public String toString() {
            return ruleId + "@" + file + ":" + line;
        }
    }

    record SinkPoint(String nodeKey, String ruleId, String function,
                     String className, String file, int line) {
    }

    /** Everything describing one invocation relevant to rule matching. */
    private record CallView(FunctionSummary owner,
                            FunctionSummary.CallFact fact,
                            ClassModel.MethodTarget target,
                            String qualifiedMethod,
                            String qualifiedStatic,
                            String bareName) {
    }

    // ---------------------------------------------------------------- DSL

    public List<Finding> analyze(Map<String, FunctionSummary> summaries, AnalysisRules rules) {
        return analyze(summaries, rules, null);
    }

    /**
     * @param model class model for Java resolution; null for legacy DSL input
     */
    public List<Finding> analyze(Map<String, FunctionSummary> summaries,
                                 AnalysisRules rules,
                                 ClassModel model) {
        FlowGraph graph = new FlowGraph();
        Map<SourceLabel, String> labelOrigin = new TreeMap<>();
        List<SinkPoint> sinkPoints = new ArrayList<>();
        JavaFlowGraphBuilder.build(summaries, rules, model, graph, labelOrigin, sinkPoints);

        Map<String, Set<SourceLabel>> taint = propagate(graph, labelOrigin);

        Map<String, AnalysisRules.SourceRule> sourceRules = new HashMap<>();
        for (AnalysisRules.SourceRule r : rules.sources()) {
            sourceRules.put(r.id(), r);
        }
        Map<String, AnalysisRules.SinkRule> sinkRules = new HashMap<>();
        for (AnalysisRules.SinkRule r : rules.sinks()) {
            sinkRules.put(r.id(), r);
        }

        Map<String, Finding> dedup = new java.util.LinkedHashMap<>();
        sinkPoints.sort(Comparator.comparing(SinkPoint::nodeKey).thenComparing(SinkPoint::ruleId));
        for (SinkPoint sink : sinkPoints) {
            Set<SourceLabel> labels = taint.getOrDefault(sink.nodeKey(), Set.of());
            List<SourceLabel> sorted = new ArrayList<>(labels);
            sorted.sort(SourceLabel::compareTo);
            for (SourceLabel label : sorted) {
                String origin = labelOrigin.get(label);
                if (origin == null) {
                    continue;
                }
                List<FlowGraph.Edge> path = shortestPath(graph, origin, sink.nodeKey());
                if (path == null) {
                    continue;
                }
                Finding finding = toFinding(model, graph, label, origin, sink, path, sourceRules, sinkRules);
                dedup.putIfAbsent(finding.fingerprint(), finding);
            }
        }

        List<Finding> findings = new ArrayList<>(dedup.values());
        findings.sort(TaintEngine::compareFindings);
        return findings;
    }

    // ---------------------------------------------------------- propagation

    private Map<String, Set<SourceLabel>> propagate(FlowGraph graph, Map<SourceLabel, String> labelOrigin) {
        Map<String, Set<SourceLabel>> taint = new HashMap<>();
        ArrayDeque<String> worklist = new ArrayDeque<>();
        for (Map.Entry<SourceLabel, String> e : labelOrigin.entrySet()) {
            taint.computeIfAbsent(e.getValue(), k -> new LinkedHashSet<>()).add(e.getKey());
            worklist.add(e.getValue());
        }
        while (!worklist.isEmpty()) {
            String node = worklist.poll();
            Set<SourceLabel> labels = taint.get(node);
            for (FlowGraph.Edge edge : graph.edgesFrom(node)) {
                Set<SourceLabel> target = taint.computeIfAbsent(edge.toKey(), k -> new LinkedHashSet<>());
                if (target.addAll(labels)) {
                    worklist.add(edge.toKey());
                }
            }
        }
        return taint;
    }

    // -------------------------------------------------------------- paths

    /** BFS shortest path with sorted neighbors: deterministic and bounded. */
    private List<FlowGraph.Edge> shortestPath(FlowGraph graph, String from, String to) {
        if (from.equals(to)) {
            return List.of();
        }
        Map<String, FlowGraph.Edge> predecessor = new HashMap<>();
        ArrayDeque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(from);
        visited.add(from);
        int expansions = 0;
        int maxExpansions = graph.nodes().size() + 1;
        while (!queue.isEmpty() && expansions++ <= maxExpansions) {
            String node = queue.poll();
            for (FlowGraph.Edge edge : graph.edgesFrom(node)) {
                if (visited.add(edge.toKey())) {
                    predecessor.put(edge.toKey(), edge);
                    if (edge.toKey().equals(to)) {
                        List<FlowGraph.Edge> path = new ArrayList<>();
                        String cursor = to;
                        while (!cursor.equals(from)) {
                            FlowGraph.Edge e = predecessor.get(cursor);
                            path.add(0, e);
                            cursor = e.fromKey();
                        }
                        return path.size() <= MAX_PATH_LENGTH ? path : path.subList(0, MAX_PATH_LENGTH);
                    }
                    queue.add(edge.toKey());
                }
            }
        }
        return null;
    }

    static String fingerprint(SourceLabel label, SinkPoint sink, List<Finding.Step> steps) {
        StringBuilder sb = new StringBuilder();
        sb.append(label).append("->").append(sink.ruleId()).append('@').append(sink.file()).append(':').append(sink.line());
        for (Finding.Step s : steps) {
            sb.append('|').append(s.file()).append(':').append(s.className()).append(':').append(s.function())
                    .append(':').append(s.variable()).append(':').append(s.line()).append(':').append(s.kind());
        }
        return sha256Hex(sb.toString());
    }

    public static String sha256Hex(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Risk ordering: severity desc, shorter path first, fingerprint asc. Total order. */
    static int compareFindings(Finding a, Finding b) {
        int c = Integer.compare(b.severity().ordinal(), a.severity().ordinal());
        if (c != 0) return c;
        c = Integer.compare(a.path().size(), b.path().size());
        if (c != 0) return c;
        return a.fingerprint().compareTo(b.fingerprint());
    }

    private static Finding toFinding(ClassModel model, FlowGraph graph,
                                     SourceLabel label, String origin,
                                     SinkPoint sink, List<FlowGraph.Edge> path,
                                     Map<String, AnalysisRules.SourceRule> sourceRules,
                                     Map<String, AnalysisRules.SinkRule> sinkRules) {
        List<Finding.Step> steps = new ArrayList<>();
        steps.add(renderStep(model, graph, origin, label.file(),
                null, label.line(), "source"));
        for (FlowGraph.Edge edge : path) {
            String kind = edge.kind();
            String variable = FlowGraph.variableOf(edge.toKey());
            String ruleId = null;
            if (FlowGraph.KIND_SINK.equals(kind)) {
                kind = "sink";
                ruleId = sink.ruleId();
            }
            steps.add(renderStep(model, graph, edge.toKey(), graph.fileOf(edge.toKey()),
                    ruleId, edge.line(), kind));
        }
        Severity sourceSev = sourceRules.containsKey(label.ruleId())
                ? sourceRules.get(label.ruleId()).severity() : Severity.MEDIUM;
        Severity sinkSev = sinkRules.containsKey(sink.ruleId())
                ? sinkRules.get(sink.ruleId()).severity() : Severity.HIGH;
        Severity severity = sourceSev.ordinal() >= sinkSev.ordinal() ? sourceSev : sinkSev;
        String fp = fingerprint(label, sink, steps);
        return new Finding(fp, label.ruleId(), sink.ruleId(), severity,
                List.copyOf(steps), Finding.STATUS_NEW);
    }

    /** Builds a path step, deriving class/method names for Java or DSL nodes. */
    private static Finding.Step renderStep(ClassModel model, FlowGraph graph, String nodeKey,
                                           String file, String sinkRuleId, int line, String kind) {
        String fn = FlowGraph.functionOf(nodeKey);
        String variable = sinkRuleId != null ? sinkRuleId : FlowGraph.variableOf(nodeKey);
        if (model == null) {
            return new Finding.Step(file, "", fn, variable, line, kind);
        }
        if (STATIC_FN.equals(fn)) {
            return new Finding.Step(file, STATIC_FN, STATIC_FN, variable, line, kind);
        }
        int hash = fn.indexOf('#');
        String className = hash < 0 ? "" : fn.substring(0, hash);
        String method = hash < 0 ? fn : fn.substring(hash + 1);
        return new Finding.Step(file, className, method, variable, line, kind);
    }
}
