package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Whole-program flow graph assembled from function summaries.
 * Nodes are (function, variable) keys; synthetic variables are "$ret" (function
 * return value) and "$sink:<line>:<ruleId>" (sink call sites).
 * Edges are stored sorted so every traversal is deterministic.
 */
public final class FlowGraph {

    /** Synthetic variable holding a function's return value. */
    public static final String RET_VAR = "$ret";

    public record Edge(String fromKey, String toKey, int line, String kind) {
    }

    /** Edge kinds appearing on reconstructed paths. */
    public static final String KIND_ASSIGN = "assign";
    public static final String KIND_ARG = "arg";
    public static final String KIND_RETURN = "return";
    public static final String KIND_CALL_RETURN = "call-return";
    public static final String KIND_SINK = "sink";
    public static final String KIND_ALIAS = "alias";

    /** Separator between function and variable in node keys; never appears in identifiers. */
    private static final String SEP = "|";

    private final Map<String, List<Edge>> adjacency = new LinkedHashMap<>();
    private final Map<String, String> nodeFile = new LinkedHashMap<>();

    public static String key(String function, String variable) {
        return function + SEP + variable;
    }

    public static String functionOf(String key) {
        int idx = key.indexOf(SEP);
        return idx < 0 ? key : key.substring(0, idx);
    }

    public static String variableOf(String key) {
        int idx = key.indexOf(SEP);
        return idx < 0 ? "" : key.substring(idx + 1);
    }

    public void registerNode(String function, String variable, String file) {
        String k = key(function, variable);
        adjacency.computeIfAbsent(k, x -> new ArrayList<>());
        nodeFile.putIfAbsent(k, file);
    }

    /** Registers an already-built node key with its originating file. */
    public void ensureNode(String key, String file) {
        adjacency.computeIfAbsent(key, x -> new ArrayList<>());
        nodeFile.putIfAbsent(key, file);
    }

    public void addEdge(String fromFn, String fromVar, String toFn, String toVar, int line, String kind) {
        String from = key(fromFn, fromVar);
        String to = key(toFn, toVar);
        adjacency.computeIfAbsent(from, x -> new ArrayList<>())
                .add(new Edge(from, to, line, kind));
        adjacency.computeIfAbsent(to, x -> new ArrayList<>());
    }

    /** Adds an edge between two fully built node keys; files attached explicitly. */
    public void addNodeEdge(String from, String to, int line, String kind, String file) {
        adjacency.computeIfAbsent(from, x -> new ArrayList<>())
                .add(new Edge(from, to, line, kind));
        adjacency.computeIfAbsent(to, x -> new ArrayList<>());
        nodeFile.putIfAbsent(from, file);
        nodeFile.putIfAbsent(to, file);
    }

    public void registerFile(String function, String variable, String file) {
        nodeFile.putIfAbsent(key(function, variable), file);
    }

    public String fileOf(String key) {
        return nodeFile.getOrDefault(key, "");
    }

    /** Outgoing edges of a node, sorted by (toKey, line, kind) for determinism. */
    public List<Edge> edgesFrom(String key) {
        List<Edge> edges = new ArrayList<>(adjacency.getOrDefault(key, List.of()));
        edges.sort(Comparator.comparing(Edge::toKey).thenComparing(Edge::line).thenComparing(Edge::kind));
        return edges;
    }

    public Set<String> nodes() {
        return adjacency.keySet();
    }
}
