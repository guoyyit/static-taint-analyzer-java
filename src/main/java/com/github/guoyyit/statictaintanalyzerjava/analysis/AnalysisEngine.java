package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.Parser;
import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaAst;
import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaParseException;
import com.github.guoyyit.statictaintanalyzerjava.lang.java.JavaParser;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Orchestrates parse -> summarize -> global taint analysis for both the legacy
 * DSL and real Java source.
 *
 * <p>Incremental: per-file summaries are reused only when both the file content
 * hash and the rules hash are unchanged. Parse failures are isolated per file;
 * one broken file never aborts the rest of the project, and each failure keeps
 * file name, 1-based line and a machine-readable reason. The global pass runs
 * over the merged summaries of all successfully parsed files.
 */
public final class AnalysisEngine {

    private final Parser parser = new Parser();
    private final JavaParser javaParser = new JavaParser();
    private final Summarizer summarizer = new Summarizer();
    private final JavaSummarizer javaSummarizer = new JavaSummarizer();
    private final TaintEngine taintEngine = new TaintEngine();

    public AnalysisResult analyze(Map<String, String> files,
                                  AnalysisRules rules,
                                  AnalysisResult previous) {
        return analyze(files, rules, previous, null);
    }

    /**
     * @param removedFiles logical paths removed relative to the parent commit
     */
    public AnalysisResult analyze(Map<String, String> files,
                                  AnalysisRules rules,
                                  AnalysisResult previous,
                                  List<String> removedFiles) {
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
        List<JavaAst.CompilationUnit> javaUnits = new ArrayList<>();
        Set<String> reparsedJavaFiles = new HashSet<>();
        Map<String, List<TypeMeta>> metasByFile = new TreeMap<>();
        Map<String, List<String>> importsByType = new TreeMap<>();
        Map<String, List<ClassModel.MethodSig>> methodsByType = new TreeMap<>();
        List<ParseFailure> failures = new ArrayList<>();
        int reused = 0;
        int reparsed = 0;
        int failed = 0;

        // Restore serializable Java structural facts for unchanged files so the
        // class model is complete even when nothing is re-parsed (e.g. restart).
        if (rulesSame && previous != null) {
            for (TypeMeta meta : previous.typeMetas()) {
                metasByFile.computeIfAbsent(metaFileOf(previous, meta), k -> new ArrayList<>()).add(meta);
            }
            importsByType.putAll(previous.importsByType());
            methodsByType.putAll(previous.methodsByType());
        }

        for (String file : fileHashes.keySet()) {
            String hash = fileHashes.get(file);
            boolean unchanged = rulesSame && previous != null
                    && hash.equals(previous.fileHashes().get(file));
            if (unchanged && prevFailures.containsKey(file)) {
                failures.add(prevFailures.get(file));
                failed++;
                continue;
            }
            if (unchanged) {
                if (isJavaFile(file)) {
                    List<TypeMeta> cachedMetas = previous == null ? null : previous.typeMetasByFile().get(file);
                    if (cachedMetas != null) {
                        metasByFile.put(file, new ArrayList<>(cachedMetas));
                    }
                    for (FunctionSummary s : prevByFile.get(file)) {
                        summaries.put(s.functionName(), s);
                    }
                } else if (prevByFile.containsKey(file)) {
                    for (FunctionSummary s : prevByFile.get(file)) {
                        putSummary(summaries, s);
                    }
                }
                reused++;
                continue;
            }
            reparsed++;
            if (isJavaFile(file)) {
                reparsedJavaFiles.add(file);
            }
            String source = files.get(file);
            if (isJavaFile(file)) {
                try {
                    JavaAst.CompilationUnit unit = javaParser.parse(file, source);
                    javaUnits.add(unit);
                    metasByFile.remove(file);
                    extractStructuralFacts(unit, metasByFile, importsByType, methodsByType, file);
                } catch (JavaParseException e) {
                    failures.add(toFailure(e));
                    failed++;
                } catch (RuntimeException e) {
                    failures.add(new ParseFailure(file, 1, ParseFailure.SYNTAX,
                            String.valueOf(e.getMessage())));
                    failed++;
                }
            } else {
                try {
                    var program = parser.parse(file, source);
                    for (var fn : program.functions()) {
                        putSummary(summaries, summarizer.summarize(fn, rules));
                    }
                } catch (RuntimeException e) {
                    failures.add(new ParseFailure(file, extractLine(e), ParseFailure.SYNTAX,
                            String.valueOf(e.getMessage())));
                    failed++;
                }
            }
        }

        // Re-summarize every Java unit against the final class model so cross-file
        // resolution sees the whole project.
        List<TypeMeta> allMetas = new ArrayList<>();
        for (List<TypeMeta> metas : metasByFile.values()) {
            allMetas.addAll(metas);
        }
        ClassModel model = ClassModel.build(allMetas, importsByType, methodsByType);
        if (!allMetas.isEmpty()) {
            for (JavaAst.CompilationUnit unit : javaUnits) {
                for (FunctionSummary s : javaSummarizer.summarizeUnit(unit, rules, model)) {
                    summaries.put(s.functionName(), s);
                }
            }
        }

        List<Finding> findings;
        if (allMetas.isEmpty()) {
            findings = taintEngine.analyze(summaries, rules, null);
        } else {
            findings = taintEngine.analyze(summaries, rules, model);
        }

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

        List<String> added = new ArrayList<>();
        if (previous != null) {
            for (String path : fileHashes.keySet()) {
                if (!previous.fileHashes().containsKey(path)) {
                    added.add(path);
                }
            }
            added.sort(String::compareTo);
        }
        List<String> removedPaths = removedFiles == null ? List.of() : List.copyOf(removedFiles);

        AnalysisResult.AnalysisStats stats = new AnalysisResult.AnalysisStats(
                reused, reparsed - failed, failed, failed, fileHashes.size());
        return new AnalysisResult(rulesHash, fileHashes, summaries, List.copyOf(stamped),
                List.copyOf(removed), stats, removedPaths, List.copyOf(added),
                List.copyOf(failures), List.copyOf(allMetas),
                Map.copyOf(importsByType), Map.copyOf(methodsByType),
                copyByFile(metasByFile));
    }

    private static Map<String, List<TypeMeta>> copyByFile(Map<String, List<TypeMeta>> source) {
        Map<String, List<TypeMeta>> copy = new TreeMap<>();
        source.forEach((k, v) -> copy.put(k, List.copyOf(v)));
        return Map.copyOf(copy);
    }

    /** Extracts serializable structural facts (types, imports, signatures) from a unit. */
    private void extractStructuralFacts(JavaAst.CompilationUnit unit,
                                        Map<String, List<TypeMeta>> metasByFile,
                                        Map<String, List<String>> importsByType,
                                        Map<String, List<ClassModel.MethodSig>> methodsByType,
                                        String file) {
        for (JavaAst.TypeDecl type : unit.types()) {
            extractType(type, unit.packageName(), unit.imports(), metasByFile,
                    importsByType, methodsByType, file);
        }
    }

    private void extractType(JavaAst.TypeDecl type, String packageName, List<String> unitImports,
                            Map<String, List<TypeMeta>> metasByFile,
                            Map<String, List<String>> importsByType,
                            Map<String, List<ClassModel.MethodSig>> methodsByType, String file) {
        List<String> supers = new ArrayList<>(type.extendsNames());
        supers.addAll(type.implementsNames());
        Map<String, String> fields = new TreeMap<>();
        List<ClassModel.MethodSig> sigs = new ArrayList<>();
        for (JavaAst.Member member : type.members()) {
            if (member instanceof JavaAst.FieldDecl field) {
                for (JavaAst.VariableDeclarator d : field.declarators()) {
                    fields.put(d.name(), field.type());
                }
            } else if (member instanceof JavaAst.MethodDecl method) {
                sigs.add(new ClassModel.MethodSig(
                        method.isConstructor() ? JavaSummarizer.INIT : method.name(),
                        method.params().size(), method.isStatic(), method.isConstructor()));
            } else if (member instanceof JavaAst.NestedTypeMember nested) {
                extractType(nested.type(), type.qualifiedName(), unitImports,
                        metasByFile, importsByType, methodsByType, file);
            }
        }
        TypeMeta meta = new TypeMeta(type.qualifiedName(), packageName, type.name(),
                List.copyOf(supers), Map.copyOf(fields), type.isInterface());
        metasByFile.computeIfAbsent(file, k -> new ArrayList<>()).add(meta);
        importsByType.put(type.qualifiedName(), List.copyOf(unitImports));
        methodsByType.put(type.qualifiedName(), List.copyOf(sigs));
    }

    /** Finds the owning file of a type meta via the previous result's index. */
    private String metaFileOf(AnalysisResult previous, TypeMeta meta) {
        return previous.typeMetasByFile().entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(m -> m.qualifiedName().equals(meta.qualifiedName())))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse("");
    }

    private static ParseFailure toFailure(JavaParseException e) {
        String reason = switch (e.reason()) {
            case LEXICAL -> ParseFailure.LEXICAL;
            case UNSUPPORTED -> ParseFailure.UNSUPPORTED;
            default -> ParseFailure.SYNTAX;
        };
        return new ParseFailure(e.file(), e.line(), reason, e.getMessage());
    }

    private static int extractLine(Throwable t) {
        String message = String.valueOf(t.getMessage());
        int idx = message.lastIndexOf("at line ");
        if (idx >= 0) {
            try {
                return Integer.parseInt(message.substring(idx + 8).replaceAll("\\D.*", ""));
            } catch (NumberFormatException ignored) {
                return 1;
            }
        }
        return 1;
    }

    static boolean isJavaFile(String path) {
        return path.endsWith(".java");
    }

    /** Name collisions resolve to the lexicographically smallest file: deterministic. */
    private static void putSummary(Map<String, FunctionSummary> summaries, FunctionSummary s) {
        FunctionSummary existing = summaries.get(s.functionName());
        if (existing == null || s.file().compareTo(existing.file()) < 0) {
            summaries.put(s.functionName(), s);
        }
    }
}
