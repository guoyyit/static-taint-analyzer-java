package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Whole-program class model: indexes types by simple/qualified name and
 * resolves method/constructor targets across packages, inheritance and
 * overloading. Built from serializable {@link TypeMeta} so it works both from a
 * fresh parse and from a reloaded commit snapshot.
 */
public final class ClassModel {

    public record MethodTarget(String classQualifiedName,
                               String methodName,
                               boolean isStatic,
                               boolean isConstructor) {
    }

    /** Methods declared on a type, name+arity keyed (value: true when static). */
    public record MethodSig(String name, int arity, boolean isStatic, boolean isConstructor) {
    }

    private record TypeEntry(TypeMeta meta, List<MethodSig> methods, List<String> imports) {
    }

    private final Map<String, TypeEntry> byQualified = new LinkedHashMap<>();
    private final Map<String, List<String>> bySimple = new LinkedHashMap<>();

    private ClassModel() {
    }

    public static String methodId(String classQualifiedName, String methodName) {
        return classQualifiedName + "#" + methodName;
    }

    public static ClassModel build(List<TypeMeta> metas,
                                   Map<String, List<String>> importsByType,
                                   Map<String, List<MethodSig>> methodsByType) {
        ClassModel model = new ClassModel();
        for (TypeMeta meta : metas) {
            List<String> imports = importsByType.getOrDefault(meta.qualifiedName(), List.of());
            List<MethodSig> methods = methodsByType.getOrDefault(meta.qualifiedName(), List.of());
            model.register(new TypeEntry(meta, List.copyOf(methods), List.copyOf(imports)));
        }
        return model;
    }

    private void register(TypeEntry entry) {
        byQualified.putIfAbsent(entry.meta().qualifiedName(), entry);
        bySimple.computeIfAbsent(entry.meta().simpleName(), k -> new ArrayList<>())
                .add(entry.meta().qualifiedName());
    }

    public boolean hasType(String qualifiedName) {
        return byQualified.containsKey(qualifiedName);
    }

    /** Declared supertypes (extends + implements) of a type, or empty if unknown. */
    public List<String> supertypesOf(String qualifiedName) {
        TypeEntry entry = byQualified.get(qualifiedName);
        return entry == null ? List.of() : entry.meta().supertypes();
    }

    public String fieldType(String contextClass, String ownerType, String fieldName) {
        String typeQ = resolveType(contextClass, stripArray(ownerType));
        TypeEntry entry = typeQ == null ? null : byQualified.get(typeQ);
        while (entry != null) {
            String t = entry.meta().fieldTypes().get(fieldName);
            if (t != null) {
                return stripArray(t);
            }
            String next = entry.meta().supertypes().isEmpty() ? null
                    : resolveType(entry.meta().qualifiedName(), entry.meta().supertypes().get(0));
            entry = next == null ? null : byQualified.get(next);
        }
        return null;
    }

    public String resolveType(String contextClass, String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        String base = stripArray(name);
        if (base.indexOf('.') >= 0) {
            return byQualified.containsKey(base) ? base : null;
        }
        TypeEntry context = byQualified.get(contextClass);
        if (context == null) {
            return resolveBySimple(base, "", List.of());
        }
        String q = contextClass;
        while (q != null) {
            if (byQualified.containsKey(q + "." + base)) {
                return q + "." + base;
            }
            int dot = q.lastIndexOf('.');
            q = dot < 0 ? null : q.substring(0, dot);
        }
        for (String imp : context.imports()) {
            if (!imp.startsWith("static ") && imp.endsWith("." + base)) {
                return imp;
            }
        }
        String samePackage = context.meta().packageName().isEmpty()
                ? base : context.meta().packageName() + "." + base;
        if (byQualified.containsKey(samePackage)) {
            return samePackage;
        }
        List<String> onDemand = new ArrayList<>();
        onDemand.add("java.lang.*");
        for (String imp : context.imports()) {
            if (imp.endsWith(".*")) {
                onDemand.add(imp);
            }
        }
        return resolveBySimple(base, context.meta().packageName(), onDemand);
    }

    private String resolveBySimple(String simple, String currentPackage, List<String> onDemand) {
        List<String> candidates = bySimple.get(simple);
        if (candidates == null) {
            return null;
        }
        for (String q : candidates) {
            TypeEntry e = byQualified.get(q);
            if (e != null && e.meta().packageName().equals(currentPackage)) {
                return q;
            }
        }
        for (String pattern : onDemand) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            for (String q : candidates) {
                TypeEntry e = byQualified.get(q);
                if (e != null && (e.meta().packageName() + ".").equals(prefix)) {
                    return q;
                }
            }
        }
        return null;
    }

    public MethodTarget resolveMethod(String contextClass, String receiverType, String methodName,
                                      int arity, boolean receiverIsType) {
        String typeName = null;
        if (receiverType != null) {
            typeName = resolveType(contextClass, stripArray(receiverType));
            if (typeName == null) {
                return null;
            }
        }
        List<String> searchOrder = new ArrayList<>();
        if (typeName != null) {
            appendChain(typeName, searchOrder, new ArrayList<>());
        } else {
            appendChain(contextClass, searchOrder, new ArrayList<>());
            for (String q : byQualified.keySet()) {
                if (!searchOrder.contains(q)) {
                    searchOrder.add(q);
                }
            }
        }
        int contextChainSize = searchOrder.size();
        MethodTarget best = null;
        for (int idx = 0; idx < searchOrder.size(); idx++) {
            TypeEntry entry = byQualified.get(searchOrder.get(idx));
            if (entry == null) {
                continue;
            }
            boolean inContextChain = idx < contextChainSize;
            for (MethodSig sig : entry.methods()) {
                boolean matchesName = sig.isConstructor()
                        ? JavaSummarizer.INIT.equals(methodName) : sig.name().equals(methodName);
                if (!matchesName || sig.arity() != arity) {
                    continue;
                }
                if (receiverIsType && !sig.isStatic() && !sig.isConstructor()) {
                    continue;
                }
                boolean unqualifiedNoReceiver = typeName == null && receiverType == null;
                if (!receiverIsType && receiverType != null && sig.isStatic()) {
                    continue;
                }
                if (unqualifiedNoReceiver && !sig.isStatic() && !inContextChain) {
                    continue;
                }
                MethodTarget candidate = new MethodTarget(entry.meta().qualifiedName(),
                        sig.isConstructor() ? JavaSummarizer.INIT : sig.name(),
                        sig.isStatic(), sig.isConstructor());
                best = pick(best, candidate);
            }
        }
        return best;
    }

    private static MethodTarget pick(MethodTarget current, MethodTarget candidate) {
        if (current == null) {
            return candidate;
        }
        return candidate.classQualifiedName().compareTo(current.classQualifiedName()) < 0
                ? candidate : current;
    }

    private void appendChain(String qualifiedName, List<String> out, List<String> visited) {
        if (qualifiedName == null || visited.contains(qualifiedName)) {
            return;
        }
        visited.add(qualifiedName);
        if (!out.contains(qualifiedName)) {
            out.add(qualifiedName);
        }
        TypeEntry entry = byQualified.get(qualifiedName);
        if (entry == null) {
            return;
        }
        for (String sup : entry.meta().supertypes()) {
            String resolved = sup.indexOf('.') < 0 ? resolveType(qualifiedName, sup) : sup;
            if (resolved != null) {
                appendChain(resolved, out, visited);
            }
        }
    }

    private static String stripArray(String type) {
        if (type == null) {
            return null;
        }
        int idx = type.indexOf('[');
        return idx < 0 ? type : type.substring(0, idx);
    }
}
