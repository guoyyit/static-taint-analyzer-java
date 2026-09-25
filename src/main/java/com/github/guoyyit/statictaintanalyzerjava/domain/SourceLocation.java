package com.github.guoyyit.statictaintanalyzerjava.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A deterministic, comparable pointer into the analyzed source tree. */
public record SourceLocation(String file, int line, int column, String methodSignature)
        implements Comparable<SourceLocation> {

    @JsonCreator
    public SourceLocation(@JsonProperty("file") String file,
                          @JsonProperty("line") int line,
                          @JsonProperty("column") int column,
                          @JsonProperty("methodSignature") String methodSignature) {
        this.file = file == null ? "" : file;
        this.line = line;
        this.column = column;
        this.methodSignature = methodSignature == null ? "" : methodSignature;
    }

    @Override
    public int compareTo(SourceLocation o) {
        int c = file.compareTo(o.file);
        if (c != 0) return c;
        c = Integer.compare(line, o.line);
        if (c != 0) return c;
        c = Integer.compare(column, o.column);
        if (c != 0) return c;
        return methodSignature.compareTo(o.methodSignature);
    }

    @Override
    public String toString() {
        return file + ":" + line + ":" + column + " in " + methodSignature;
    }
}
