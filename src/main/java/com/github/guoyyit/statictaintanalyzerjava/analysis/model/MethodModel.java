package com.github.guoyyit.statictaintanalyzerjava.analysis.model;

import com.github.javaparser.ast.body.MethodDeclaration;

import java.util.List;

/** A parsed method plus its stable signature {@code Class#name(Type,Type)}. */
public record MethodModel(String signature,
                          String className,
                          String methodName,
                          List<String> paramNames,
                          List<String> paramTypes,
                          String file,
                          MethodDeclaration declaration) {

    public int arity() {
        return paramNames.size();
    }
}
