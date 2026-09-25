package com.github.guoyyit.statictaintanalyzerjava.analysis.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Whole-program model: methods, call graph (both directions) and field
 * read/write index. All collections use sorted/insertion-deterministic
 * structures so analysis results are reproducible.
 */
public final class ProgramModel {

    private final Map<String, MethodModel> bySignature = new TreeMap<>();
    private final Map<String, List<MethodModel>> byName = new TreeMap<>();
    private final Map<String, Set<String>> callersToCallees = new TreeMap<>();
    private final Map<String, Set<String>> calleesToCallers = new TreeMap<>();
    private final Map<String, Set<String>> fieldWriters = new TreeMap<>();
    private final Map<String, Set<String>> fieldReaders = new TreeMap<>();
    private final Map<String, Set<String>> fileToMethods = new TreeMap<>();
    private final Map<String, Map<String, String>> classFieldTypes = new TreeMap<>();
    private final Map<String, String> simpleClassNameToFqn = new TreeMap<>();

    public void addMethod(MethodModel m) {
        bySignature.put(m.signature(), m);
        byName.computeIfAbsent(m.methodName(), k -> new ArrayList<>()).add(m);
        fileToMethods.computeIfAbsent(m.file(), k -> new TreeSet<>()).add(m.signature());
    }

    public void addCallEdge(String caller, String callee) {
        callersToCallees.computeIfAbsent(caller, k -> new TreeSet<>()).add(callee);
        calleesToCallers.computeIfAbsent(callee, k -> new TreeSet<>()).add(caller);
    }

    public void addFieldWrite(String field, String methodSignature) {
        fieldWriters.computeIfAbsent(field, k -> new TreeSet<>()).add(methodSignature);
    }

    public void addFieldRead(String field, String methodSignature) {
        fieldReaders.computeIfAbsent(field, k -> new TreeSet<>()).add(methodSignature);
    }

    /** Registers a known class so simple names resolve to qualified names. */
    public void addClass(String className) {
        simpleClassNameToFqn.putIfAbsent(simpleName(className), className);
    }

    public void addClassField(String className, String fieldName, String typeName) {
        classFieldTypes.computeIfAbsent(className, k -> new TreeMap<>()).put(fieldName, typeName);
        addClass(className);
    }

    /** Resolves a possibly simple class name to the program-known qualified name. */
    public String resolveClassName(String name) {
        if (name == null || name.isEmpty()) {
            return "";
        }
        return simpleClassNameToFqn.getOrDefault(name, name);
    }

    private static String simpleName(String className) {
        int dot = className.lastIndexOf('.');
        return dot < 0 ? className : className.substring(dot + 1);
    }

    /** Field types declared by a class: field name -> declared type name. */
    public Map<String, String> fieldTypesOf(String className) {
        return classFieldTypes.getOrDefault(className, Map.of());
    }

    public MethodModel bySignature(String signature) {
        return bySignature.get(signature);
    }

    public List<MethodModel> byName(String name) {
        return byName.getOrDefault(name, List.of());
    }

    public List<MethodModel> methods() {
        return List.copyOf(bySignature.values());
    }

    public Set<String> calleesOf(String caller) {
        return callersToCallees.getOrDefault(caller, Set.of());
    }

    public Set<String> callersOf(String callee) {
        return calleesToCallers.getOrDefault(callee, Set.of());
    }

    public Set<String> writersOfField(String field) {
        return fieldWriters.getOrDefault(field, Set.of());
    }

    public Set<String> readersOfField(String field) {
        return fieldReaders.getOrDefault(field, Set.of());
    }

    public Set<String> methodsInFile(String file) {
        return fileToMethods.getOrDefault(file, Set.of());
    }

    /** All known field keys ({@code Class.field}) from declarations and accesses. */
    public Set<String> allFieldKeys() {
        Set<String> keys = new TreeSet<>(fieldWriters.keySet());
        keys.addAll(fieldReaders.keySet());
        classFieldTypes.forEach((cls, fields) ->
                fields.keySet().forEach(f -> keys.add(cls + "." + f)));
        return keys;
    }

    public Set<String> allFiles() {
        return Set.copyOf(fileToMethods.keySet());
    }
}
