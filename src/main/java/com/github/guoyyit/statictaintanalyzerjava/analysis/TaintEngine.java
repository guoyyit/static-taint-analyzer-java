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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Deterministic bounded taint propagation over the global flow graph.
 *
 * Propagation is a least-fixpoint union of source labels over a finite graph, so
 * loops, recursion and aliases terminate with order-independent results. Each
 * (source, sink) pair is then materialized as one shortest path found by BFS with
 * sorted neighbors, which makes findings stable and reproducible.
 */
public final class TaintEngine {

    /** Max steps of a reconstructed path; keeps results bounded on recursion. */
    public static final int MAX_PATH_LENGTH = 64;

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

    private record SinkPoint(String nodeKey, String ruleId, String function, String file, int line) {
    }

    public List<Finding> analyze(Map<String, FunctionSummary> summaries, AnalysisRules rules) {
        FlowGraph graph = new FlowGraph();
        Map<SourceLabel, String> labelOrigin = new TreeMap<>();
        List<SinkPoint> sinkPoints = new ArrayList<>();
        buildGraph(summaries, graph, labelOrigin, sinkPoints);

        Map<String, Set<SourceLabel>> taint = propagate(graph, labelOrigin);

        Map<String, AnalysisRules.SourceRule> sourceRules = new HashMap<>();
        for (AnalysisRules.SourceRule r : rules.sources()) {
            sourceRules.put(r.id(), r);
        }
        Map<String, AnalysisRules.SinkRule> sinkRules = new HashMap<>();
        for (AnalysisRules.SinkRule r : rules.sinks()) {
            sinkRules.put(r.id(), r);
        }

        Map<String, Finding> dedup = new LinkedHashMap<>();
        sinkPoints.sort(Comparator.comparing(SinkPoint::nodeKey).thenComparing(SinkPoint::ruleId));
        for (SinkPoint sink : sinkPoints) {
            Set<SourceLabel> labels = taint.getOrDefault(sink.nodeKey(), Set.of());
            List<SourceLabel> sorted = new ArrayList<>(labels);
            CollectionsSort(sorted);
            for (SourceLabel label : sorted) {
                String origin = labelOrigin.get(label);
                if (origin == null) {
                    continue;
                }
                List<FlowGraph.Edge> path = shortestPath(graph, origin, sink.nodeKey());
                if (path == null) {
                    continue;
                }
                Finding finding = toFinding(graph, label, origin, sink, path, sourceRules, sinkRules);
                dedup.putIfAbsent(finding.fingerprint(), finding);
            }
        }

        List<Finding> findings = new ArrayList<>(dedup.values());
        findings.sort(TaintEngine::compareFindings);
        return findings;
    }

    private static void CollectionsSort(List<SourceLabel> labels) {
        labels.sort(SourceLabel::compareTo);
    }

    // ---------------------------------------------------------------- graph

    private void buildGraph(Map<String, FunctionSummary> summaries,
                            FlowGraph graph,
                            Map<SourceLabel, String> labelOrigin,
                            List<SinkPoint> sinkPoints) {
        for (FunctionSummary fn : summaries.values()) {
            for (String param : fn.params()) {
                graph.registerFile(fn.functionName(), param, fn.file());
            }
            for (FunctionSummary.AssignFact a : fn.assignments()) {
                graph.registerFile(fn.functionName(), a.dst(), fn.file());
                for (String src : a.srcs()) {
                    graph.registerFile(fn.functionName(), src, fn.file());
                    graph.addEdge(fn.functionName(), src, fn.functionName(), a.dst(), a.line(), FlowGraph.KIND_ASSIGN);
                }
            }
            for (FunctionSummary.ReturnFact r : fn.returns()) {
                for (String src : r.srcs()) {
                    graph.registerFile(fn.functionName(), src, fn.file());
                    graph.addEdge(fn.functionName(), src, fn.functionName(), FlowGraph.RET_VAR, r.line(), FlowGraph.KIND_RETURN);
                }
            }
        }
        for (FunctionSummary fn : summaries.values()) {
            for (FunctionSummary.CallFact call : fn.calls()) {
                FunctionSummary callee = summaries.get(call.callee());
                if (callee != null) {
                    int bound = Math.min(call.argVars().size(), callee.params().size());
                    for (int i = 0; i < bound; i++) {
                        graph.registerFile(fn.functionName(), call.argVars().get(i), fn.file());
                        graph.registerFile(callee.functionName(), callee.params().get(i), callee.file());
                        graph.addEdge(fn.functionName(), call.argVars().get(i),
                                callee.functionName(), callee.params().get(i), call.line(), FlowGraph.KIND_ARG);
                    }
                    if (call.dst() != null) {
                        graph.registerFile(fn.functionName(), call.dst(), fn.file());
                        graph.addEdge(callee.functionName(), FlowGraph.RET_VAR,
                                fn.functionName(), call.dst(), call.line(), FlowGraph.KIND_CALL_RETURN);
                    }
                } else if (call.dst() != null) {
                    // Unknown callee: conservatively pass argument taint to the result.
                    for (String argVar : call.argVars()) {
                        graph.registerFile(fn.functionName(), argVar, fn.file());
                        graph.registerFile(fn.functionName(), call.dst(), fn.file());
                        graph.addEdge(fn.functionName(), argVar, fn.functionName(), call.dst(),
                                call.line(), FlowGraph.KIND_CALL_RETURN);
                    }
                }
            }
            for (FunctionSummary.SourceFact s : fn.sources()) {
                graph.registerFile(fn.functionName(), s.dst(), fn.file());
                labelOrigin.put(new SourceLabel(s.ruleId(), fn.file(), s.line()),
                        FlowGraph.key(fn.functionName(), s.dst()));
            }
            for (FunctionSummary.SinkFact s : fn.sinks()) {
                String sinkVar = "$sink:" + s.line() + ":" + s.ruleId();
                graph.registerFile(fn.functionName(), sinkVar, fn.file());
                for (String argVar : s.argVars()) {
                    graph.registerFile(fn.functionName(), argVar, fn.file());
                    graph.addEdge(fn.functionName(), argVar, fn.functionName(), sinkVar, s.line(), FlowGraph.KIND_SINK);
                }
                sinkPoints.add(new SinkPoint(FlowGraph.key(fn.functionName(), sinkVar),
                        s.ruleId(), fn.functionName(), fn.file(), s.line()));
            }
        }
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

    private Finding toFinding(FlowGraph graph,
                              SourceLabel label,
                              String origin,
                              SinkPoint sink,
                              List<FlowGraph.Edge> path,
                              Map<String, AnalysisRules.SourceRule> sourceRules,
                              Map<String, AnalysisRules.SinkRule> sinkRules) {
        List<Finding.Step> steps = new ArrayList<>();
        steps.add(new Finding.Step(label.file(), FlowGraph.functionOf(origin),
                FlowGraph.variableOf(origin), label.line(), "source"));
        for (FlowGraph.Edge edge : path) {
            String kind = edge.kind();
            String variable = FlowGraph.variableOf(edge.toKey());
            if (FlowGraph.KIND_SINK.equals(kind)) {
                kind = "sink";
                variable = sink.ruleId();
            }
            steps.add(new Finding.Step(graph.fileOf(edge.toKey()), FlowGraph.functionOf(edge.toKey()),
                    variable, edge.line(), kind));
        }
        Severity sourceSev = sourceRules.containsKey(label.ruleId())
                ? sourceRules.get(label.ruleId()).severity() : Severity.MEDIUM;
        Severity sinkSev = sinkRules.containsKey(sink.ruleId())
                ? sinkRules.get(sink.ruleId()).severity() : Severity.HIGH;
        Severity severity = sourceSev.ordinal() >= sinkSev.ordinal() ? sourceSev : sinkSev;
        String fingerprint = fingerprint(label, sink, steps);
        return new Finding(fingerprint, label.ruleId(), sink.ruleId(), severity,
                List.copyOf(steps), Finding.STATUS_NEW);
    }

    static String fingerprint(SourceLabel label, SinkPoint sink, List<Finding.Step> steps) {
        StringBuilder sb = new StringBuilder();
        sb.append(label).append("->").append(sink.ruleId()).append('@').append(sink.file()).append(':').append(sink.line());
        for (Finding.Step s : steps) {
            sb.append('|').append(s.file()).append(':').append(s.function()).append(':')
                    .append(s.variable()).append(':').append(s.line()).append(':').append(s.kind());
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
}
