package com.github.guoyyit.statictaintanalyzerjava.analysis;

import java.util.List;
import java.util.Map;

/**
 * Serializable structural facts of one type used for cross-class resolution.
 * Independent of the Java AST, so it safely round-trips through the commit
 * JSON store. Field names map to their declared (normalized) type names.
 */
public record TypeMeta(String qualifiedName,
                       String packageName,
                       String simpleName,
                       List<String> supertypes,
                       Map<String, String> fieldTypes,
                       boolean isInterface) {

    public TypeMeta {
        supertypes = supertypes == null ? List.of() : List.copyOf(supertypes);
        fieldTypes = fieldTypes == null ? Map.of() : Map.copyOf(fieldTypes);
    }
}
