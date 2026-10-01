package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Whole-project index of Java type declarations, used to resolve method and
 * field references across classes and packages.
 *
 * <p>Resolution is purely structural (no external classpath): project types,
 * explicit/on-demand imports, the declaring package and {@code java.lang} are
 * considered, in that priority. Overloads are filtered by arity. When several
 * targets remain (inheritance / interfaces / unresolved receivers), all of them
 * are returned: the analysis stays soundly over-approximate while remaining
 * deterministic (sorted keys).
 */
public final class ClassIndex {

    private static final List<String> JAVA_LANG = List.of(
            "java.lang.String", "java.lang.StringBuilder", "java.lang.StringBuffer",
            "java.lang.Object", "java.lang.Integer", "java.lang.Long", "java.lang.Boolean",
            "java.lang.Double", "java.lang.Float", "java.lang.Short", "java.lang.Byte",
            "java.lang.Character", "java.lang.Number", "java.lang.Enum", "java.lang.Math",
            "java.lang.System", "java.lang.Throwable", "java.lang.Exception",
            "java.lang.RuntimeException", "java.lang.Iterable", "java.lang.Comparable");

    private record TypeInfo(String fqn, String packageName, List<String> imports, List<String> supers) {
    }

    private final Map<String, TypeInfo> types = new LinkedHashMap<>();
    private final Map<String, List<FunctionSummary>> methods = new LinkedHashMap<>();

    private ClassIndex() {
    }

    public static ClassIndex build(List<FunctionSummary> summaries) {
        ClassIndex index = new ClassIndex();
        for (FunctionSummary s : summaries) {
            if (s.ownerClass() == null || s.ownerClass().isEmpty()) {
                continue;
            }
            index.methods.computeIfAbsent(s.functionName(), k -> new ArrayList<>());
            if (!index.methods.get(s.functionName()).contains(s)) {
                index.methods.get(s.functionName()).add(s);
            }
            index.types.merge(s.ownerClass(),
                    new TypeInfo(s.ownerClass(), s.packageName(), s.imports(), s.supers()),
                    (a, b) -> new TypeInfo(a.fqn(), a.packageName(),
                            mergeFirst(a.imports(), b.imports()), mergeFirst(a.supers(), b.supers())));
        }
        return index;
    }

    private static List<String> mergeFirst(List<String> a, List<String> b) {
        if (a != null && !a.isEmpty()) {
            return a;
        }
        return b == null ? List.of() : b;
    }

    public boolean isJava(String ownerClass) {
        return ownerClass != null && !ownerClass.isEmpty();
    }

    /** Resolves a type token as seen from a referencing member to an FQN. */
    String resolveType(String token, FunctionSummary from) {
        return resolveTypeIn(token, from.packageName(), from.imports(), from.ownerClass());
    }

    private String resolveTypeIn(String token, String packageName, List<String> imports, String ownerClass) {
        if (token == null || token.isEmpty()) {
            return "";
        }
        if (types.containsKey(token)) {
            return token;
        }
        String simple = simpleName(token);
        for (String imp : imports) {
            if (imp.endsWith(":static") || imp.endsWith(".*")) {
                continue;
            }
            if (imp.equals(token) || simpleName(imp).equals(simple)) {
                return imp;
            }
        }
        // 3. same package
        String candidate = packageName.isEmpty() ? simple : packageName + "." + simple;
        if (types.containsKey(candidate)) {
            return candidate;
        }
        // 4. on-demand imports (own package handled above)
        for (String imp : imports) {
            if (imp.endsWith(".*") && !imp.endsWith(":static")) {
                String pkg = imp.substring(0, imp.length() - 2);
                String guess = pkg + "." + simple;
                if (types.containsKey(guess)) {
                    return guess;
                }
            }
        }
        // 5. nested types of the owner
        if (ownerClass != null && types.containsKey(ownerClass + "." + simple)) {
            return ownerClass + "." + simple;
        }
        // 6. java.lang
        for (String jl : JAVA_LANG) {
            if (simpleName(jl).equals(simple)) {
                return jl;
            }
        }
        return token.contains(".") ? token : candidate;
    }

    private static String simpleName(String token) {
        int dot = token.lastIndexOf('.');
        return dot < 0 ? token : token.substring(dot + 1);
    }

    /**
     * Resolves a call site to concrete method summaries.
     *
     * @param callee     textual callee ("<init>" for constructors, else method name)
     * @param ownerTokens owner candidates collected by the frontend
     * @param arity       number of actual arguments
     * @param caller      the enclosing member
     */
    public List<FunctionSummary> resolveMethods(String callee, List<String> ownerTokens,
                                                int arity, FunctionSummary caller) {
        Set<String> keys = new LinkedHashSet<>();
        boolean constructor = "<init>".equals(callee);
        for (String token : ownerTokens) {
            if (token == null || token.isEmpty()) {
                continue;
            }
            String fqn = resolveType(token, caller);
            if (constructor) {
                collectConstructorKeys(fqn, arity, keys, new LinkedHashSet<>());
            } else {
                collectMethodKeys(fqn, callee, arity, keys, new LinkedHashSet<>());
            }
        }
        if (!constructor) {
            // Unqualified / unresolved receiver: same-class lookup plus interface
            // implementors and static-import targets keep calls connected.
            collectMethodKeys(caller.ownerClass(), callee, arity, keys, new LinkedHashSet<>());
            for (String imp : caller.imports()) {
                if (imp.endsWith(":static") && !imp.endsWith(".*")) {
                    int dot = imp.lastIndexOf('.');
                    if (dot > 0 && imp.substring(dot + 1).equals(callee)) {
                        collectMethodKeys(imp.substring(0, dot), callee, arity, keys, new LinkedHashSet<>());
                    }
                }
            }
        }
        List<FunctionSummary> result = new ArrayList<>();
        for (String key : keys) {
            List<FunctionSummary> list = methods.get(key);
            if (list != null) {
                result.addAll(list);
            }
        }
        return result;
    }

    private void collectConstructorKeys(String fqn, int arity, Set<String> keys, Set<String> seen) {
        if (fqn == null || fqn.isEmpty() || !seen.add(fqn)) {
            return;
        }
        String prefix = fqn + "#<init>(";
        for (String key : methods.keySet()) {
            if (key.startsWith(prefix)) {
                FunctionSummary s = methods.get(key).get(0);
                // $this plus declared parameters
                int declared = s.params().size() - (s.instance() ? 1 : 0);
                if (declared == arity) {
                    keys.add(key);
                }
            }
        }
        TypeInfo info = types.get(fqn);
        if (info != null) {
            for (String sup : info.supers()) {
                collectConstructorKeys(resolveTypeIn(sup, info.packageName(), info.imports(), info.fqn()),
                        arity, keys, seen);
            }
        }
    }

    private void collectMethodKeys(String fqn, String callee, int arity, Set<String> keys, Set<String> seen) {
        if (fqn == null || fqn.isEmpty() || !seen.add(fqn)) {
            return;
        }
        String prefix = fqn + "#" + callee + "(";
        for (String key : methods.keySet()) {
            if (key.startsWith(prefix)) {
                FunctionSummary s = methods.get(key).get(0);
                int declared = s.params().size() - (s.instance() ? 1 : 0);
                if (declared == arity) {
                    keys.add(key);
                }
            }
        }
        TypeInfo info = types.get(fqn);
        if (info != null) {
            for (String sup : info.supers()) {
                collectMethodKeys(resolveTypeIn(sup, info.packageName(), info.imports(), info.fqn()),
                        callee, arity, keys, seen);
            }
        }
    }

    /** FQNs of concrete field owners for a field name seen from a member. */
    public List<String> resolveFieldOwners(String field, List<String> ownerTokens, FunctionSummary caller) {
        Set<String> fqns = new LinkedHashSet<>();
        boolean sawThis = false;
        for (String token : ownerTokens) {
            if (token == null || token.isEmpty() || "$this*".equals(token)) {
                if ("$this*".equals(token)) {
                    fqns.add(caller.ownerClass());
                }
                continue;
            }
            if (looksLikeType(token)) {
                fqns.add(resolveType(token, caller));
            } else if (THIS_KEYWORDS.contains(token)) {
                sawThis = true;
            }
        }
        if (sawThis) {
            fqns.add(caller.ownerClass());
        }
        return unifyFieldOwners(field, new ArrayList<>(fqns), caller);
    }

    /**
     * Lifts concrete owners to the classes that declare a field along their
     * supertype chain, so a write in a subclass ({@code this.req = u} in
     * {@code Main}) and a read in the declaring class ({@code this.req} in
     * {@code Base}) resolve to the same global field node. When the field is
     * not found in a chain, the original concrete owner is kept (over-approx).
     */
    private List<String> unifyFieldOwners(String field, List<String> concrete, FunctionSummary caller) {
        Set<String> unified = new LinkedHashSet<>();
        for (String owner : concrete) {
            String declarer = findFieldDeclarer(owner, field, new LinkedHashSet<>(), caller);
            unified.add(declarer != null ? declarer : owner);
        }
        return new ArrayList<>(unified);
    }

    private String findFieldDeclarer(String fqn, String field, Set<String> seen, FunctionSummary caller) {
        if (fqn == null || fqn.isEmpty() || !seen.add(fqn)) {
            return null;
        }
        if (declaresField(fqn, field)) {
            return fqn;
        }
        TypeInfo info = types.get(fqn);
        if (info == null) {
            return null;
        }
        for (String sup : info.supers()) {
            // A supertype token may already be an FQN or a simple name resolvable
            // from the referencing member's context; try both contexts.
            String fromOwner = resolveTypeIn(sup, info.packageName(), info.imports(), info.fqn());
            String declarer = findFieldDeclarer(fromOwner, field, seen, caller);
            if (declarer == null && caller != null) {
                String fromCaller = resolveType(sup, caller);
                if (!fromCaller.equals(fromOwner)) {
                    declarer = findFieldDeclarer(fromCaller, field, seen, caller);
                }
            }
            if (declarer != null) {
                return declarer;
            }
        }
        return null;
    }

    private boolean declaresField(String fqn, String field) {
        for (List<FunctionSummary> members : methods.values()) {
            for (FunctionSummary s : members) {
                if (s.ownerClass().equals(fqn)
                        && ("field:" + field).equals(s.memberName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean looksLikeType(String token) {
        if (token.contains(".")) {
            // qualified token: first segment capitalized, or an already-resolved FQN
            String head = token.substring(0, token.indexOf('.'));
            return Character.isUpperCase(head.charAt(0));
        }
        return !token.isEmpty() && Character.isUpperCase(token.charAt(0));
    }

    private static final Set<String> THIS_KEYWORDS = Set.of("this", "super");

    public Set<String> typeFqns() {
        return Collections.unmodifiableSet(types.keySet());
    }

    /** Resolves the field owners including supertypes, used when registering edges. */
    public List<String> expandFieldOwners(List<String> owners) {
        Set<String> all = new LinkedHashSet<>(owners);
        for (String owner : owners) {
        TypeInfo info = types.get(owner);
        if (info != null) {
            for (String sup : info.supers()) {
                all.add(resolveTypeIn(sup, info.packageName(), info.imports(), info.fqn()));
            }
        }
        }
        return new ArrayList<>(all);
    }

}
