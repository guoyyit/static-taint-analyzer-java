package com.github.guoyyit.statictaintanalyzerjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * File-based immutable commit store with atomic publish:
 * write to a journal dir, rename into commits/, then atomically replace HEAD.
 * Readers only ever see the commit referenced by HEAD. recover() drops
 * half-written journals after a crash; orphan commits are complete but
 * unreferenced, so they are kept (never mistaken for partial writes).
 */
public final class CommitStore {

    public record CommitMeta(String commitId, String jobId, String parentId,
                             String rulesHash, long createdAt, List<String> removedFingerprints) {
    }

    public record Commit(CommitMeta meta, AnalysisResult result) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final Path projectDir;
    private final Path commitsDir;
    private final Path journalDir;
    private final Path headFile;

    public CommitStore(Path projectDir) {
        this.projectDir = projectDir;
        this.commitsDir = projectDir.resolve("commits");
        this.journalDir = projectDir.resolve("journal");
        this.headFile = projectDir.resolve("HEAD");
    }

    /** Atomically publish a new commit and move HEAD. Called by the single writer thread. */
    public Commit publish(String jobId, AnalysisResult result) {
        try {
            Files.createDirectories(commitsDir);
            Files.createDirectories(journalDir);
            String parentId = head().map(c -> c.meta().commitId()).orElse(null);
            String commitId = commitIdOf(jobId, parentId, result.rulesHash());
            CommitMeta meta = new CommitMeta(commitId, jobId, parentId, result.rulesHash(),
                    System.currentTimeMillis(), result.removedFingerprints());
            Commit commit = new Commit(meta, result);

            Path tmp = journalDir.resolve(commitId + ".tmp");
            deleteRecursively(tmp);
            Files.createDirectories(tmp);
            writeJson(tmp.resolve("meta.json"), meta);
            writeJson(tmp.resolve("result.json"), result);
            Path target = commitsDir.resolve(commitId);
            deleteRecursively(target);
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);

            Path headTmp = projectDir.resolve("HEAD.tmp");
            Files.writeString(headTmp, commitId, StandardCharsets.UTF_8);
            Files.move(headTmp, headFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            return commit;
        } catch (IOException e) {
            throw new UncheckedIOException("failed to publish commit", e);
        }
    }

    public Optional<Commit> head() {
        try {
            if (!Files.exists(headFile)) {
                return Optional.empty();
            }
            String commitId = Files.readString(headFile, StandardCharsets.UTF_8).trim();
            if (commitId.isEmpty()) {
                return Optional.empty();
            }
            return load(commitId);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public Optional<Commit> load(String commitId) {
        try {
            Path dir = commitsDir.resolve(commitId);
            if (!Files.isDirectory(dir)) {
                return Optional.empty();
            }
            CommitMeta meta = MAPPER.readValue(dir.resolve("meta.json").toFile(), CommitMeta.class);
            AnalysisResult result = MAPPER.readValue(dir.resolve("result.json").toFile(), AnalysisResult.class);
            return Optional.of(new Commit(meta, result));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public List<CommitMeta> list() {
        List<CommitMeta> metas = new ArrayList<>();
        if (!Files.isDirectory(commitsDir)) {
            return metas;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(commitsDir)) {
            for (Path dir : stream) {
                Path metaFile = dir.resolve("meta.json");
                if (Files.exists(metaFile)) {
                    metas.add(MAPPER.readValue(metaFile.toFile(), CommitMeta.class));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        metas.sort(Comparator.comparingLong(CommitMeta::createdAt).thenComparing(CommitMeta::commitId));
        return metas;
    }

    public boolean hasCommitForJob(String jobId) {
        for (CommitMeta meta : list()) {
            if (meta.jobId().equals(jobId)) {
                return true;
            }
        }
        return false;
    }

    /** Crash recovery: discard partial journals; drop a dangling HEAD pointer. */
    public void recover() {
        try {
            if (Files.isDirectory(journalDir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(journalDir)) {
                    for (Path p : stream) {
                        deleteRecursively(p);
                    }
                }
            }
            if (Files.exists(headFile)) {
                String commitId = Files.readString(headFile, StandardCharsets.UTF_8).trim();
                if (!commitId.isEmpty() && !Files.isDirectory(commitsDir.resolve(commitId))) {
                    Files.delete(headFile);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("recovery failed", e);
        }
    }

    private static String commitIdOf(String jobId, String parentId, String rulesHash) {
        String seed = jobId + "|" + (parentId == null ? "root" : parentId) + "|" + rulesHash;
        return "c" + com.github.guoyyit.statictaintanalyzerjava.analysis.TaintEngine
                .sha256Hex(seed).substring(0, 16);
    }

    private static void writeJson(Path file, Object value) throws IOException {
        Files.writeString(file, MAPPER.writeValueAsString(value), StandardCharsets.UTF_8);
    }

    static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
    }
}
