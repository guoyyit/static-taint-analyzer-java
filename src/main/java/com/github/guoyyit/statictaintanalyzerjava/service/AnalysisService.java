package com.github.guoyyit.statictaintanalyzerjava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisEngine;
import com.github.guoyyit.statictaintanalyzerjava.analysis.AnalysisResult;
import com.github.guoyyit.statictaintanalyzerjava.analysis.Finding;
import com.github.guoyyit.statictaintanalyzerjava.analysis.ParseFailure;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;
import com.github.guoyyit.statictaintanalyzerjava.store.AuditLog;
import com.github.guoyyit.statictaintanalyzerjava.store.CommitStore;
import com.github.guoyyit.statictaintanalyzerjava.store.ExemptionStore;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Coordinates analysis jobs, atomic commits and consistent reads.
 *
 * A single background executor serializes job execution, so there is exactly one
 * writer. Every job is persisted before it runs; after a crash, unfinished jobs
 * are re-executed from the last committed position (idempotent commit ids make
 * re-execution safe). Readers only observe the immutable commit referenced by
 * HEAD, so they never see partial state.
 */
public class AnalysisService {

    public enum JobStatus { PENDING, RUNNING, COMMITTED, FAILED }

    public record JobView(String jobId, JobStatus status, String commitId, String error) {
    }

    public record FindingsView(String commitId, String rulesHash, List<Finding> findings,
                               List<String> removedFingerprints, Set<String> suppressedFingerprints,
                               List<String> removedFiles, List<String> addedFiles,
                               List<ParseFailure> parseFailures,
                               int reusedFiles, int reparsedFiles, int unchangedFiles,
                               int failedFiles, int totalFiles) {
    }

    /** Persisted job envelope: the unit of crash recovery. */
    record JobState(String jobId, String status, String rules, Map<String, String> files,
                    String commitId, String error) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern PROJECT_NAME = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    private record ProjectContext(Path dir, CommitStore commits, ExemptionStore exemptions) {
    }

    private final Path dataDir;
    private final ExecutorService executor;
    private final AnalysisEngine engine = new AnalysisEngine();
    private final Map<String, ProjectContext> projects = new ConcurrentHashMap<>();
    private final Map<String, JobView> jobViews = new ConcurrentHashMap<>();

    public AnalysisService(Path dataDir) {
        this.dataDir = dataDir;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "taint-analysis-writer");
            t.setDaemon(true);
            return t;
        });
    }

    // ------------------------------------------------------------- submit

    /** Submit an analysis job; persists it first, then executes asynchronously. */
    public String submit(String project, Map<String, String> files, String rulesJson, String jobId) {
        return submit(project, files, rulesJson, jobId, List.of());
    }

    /**
     * Submit an analysis over inline files plus recursively discovered project
     * directories. Directory contents are merged into {@code files}; on key
     * collision inline files win (explicit submission is authoritative).
     */
    public String submit(String project, Map<String, String> files, String rulesJson,
                         String jobId, List<String> directoryRoots) {
        validateProject(project);
        AnalysisRules.fromJson(rulesJson); // fail fast on invalid rules
        String id = (jobId == null || jobId.isBlank()) ? "job-" + UUID.randomUUID() : jobId;
        ProjectContext ctx = context(project);
        if (ctx.commits().hasCommitForJob(id)) {
            return id; // idempotent: already committed
        }
        Map<String, String> merged = new java.util.TreeMap<>();
        if (directoryRoots != null) {
            DirectoryScanner scanner = new DirectoryScanner();
            for (String rootPath : directoryRoots) {
                try {
                    Map<String, String> discovered = scanner.scan(Path.of(rootPath), "");
                    merged.putAll(discovered);
                } catch (IOException e) {
                    throw new UncheckedIOException("cannot scan directory: " + rootPath, e);
                }
            }
        }
        if (files != null) {
            merged.putAll(files);
        }
        JobState state = new JobState(id, JobStatus.PENDING.name(), rulesJson,
                Map.copyOf(merged), null, null);
        writeJob(ctx, state);
        jobViews.put(jobKey(project, id), new JobView(id, JobStatus.PENDING, null, null));
        executor.submit(() -> execute(ctx, project, state));
        return id;
    }

    private void execute(ProjectContext ctx, String project, JobState state) {
        String key = jobKey(project, state.jobId());
        try {
            if (ctx.commits().hasCommitForJob(state.jobId())) {
                markCommitted(ctx, key, state);
                return;
            }
            jobViews.put(key, new JobView(state.jobId(), JobStatus.RUNNING, null, null));
            writeJob(ctx, new JobState(state.jobId(), JobStatus.RUNNING.name(), state.rules(),
                    state.files(), null, null));

            AnalysisRules rules = AnalysisRules.fromJson(state.rules());
            AnalysisResult previous = ctx.commits().head().map(CommitStore.Commit::result).orElse(null);
            String previousRulesHash = previous == null ? null : previous.rulesHash();

            List<String> removedPaths = new ArrayList<>();
            if (previous != null) {
                for (String oldPath : previous.fileHashes().keySet()) {
                    if (!state.files().containsKey(oldPath)) {
                        removedPaths.add(oldPath);
                    }
                }
                removedPaths.sort(String::compareTo);
            }
            AnalysisResult result = engine.analyze(state.files(), rules, previous, removedPaths);
            CommitStore.Commit commit = ctx.commits().publish(state.jobId(), result);

            if (previousRulesHash != null && !previousRulesHash.equals(result.rulesHash())) {
                ctx.exemptions().auditLog().append("system", "RULES_CHANGED",
                        "from=" + previousRulesHash + " to=" + result.rulesHash()
                                + " commit=" + commit.meta().commitId());
            }
            ctx.exemptions().auditLog().append("system", "ANALYSIS_COMMITTED",
                    "commit=" + commit.meta().commitId() + " job=" + state.jobId()
                            + " findings=" + result.findings().size()
                            + " removed=" + result.removedFingerprints().size()
                            + " reusedFiles=" + result.stats().reusedFiles()
                            + " reparsedFiles=" + result.stats().reparsedFiles());
            markCommitted(ctx, key, new JobState(state.jobId(), JobStatus.COMMITTED.name(),
                    state.rules(), state.files(), commit.meta().commitId(), null));
        } catch (Throwable t) {
            jobViews.put(key, new JobView(state.jobId(), JobStatus.FAILED, null, String.valueOf(t)));
            try {
                writeJob(ctx, new JobState(state.jobId(), JobStatus.FAILED.name(), state.rules(),
                        state.files(), null, String.valueOf(t)));
            } catch (Throwable ignored) {
                // keep original failure
            }
        }
    }

    private void markCommitted(ProjectContext ctx, String key, JobState state) {
        String commitId = state.commitId();
        if (commitId == null) {
            commitId = ctx.commits().list().stream()
                    .filter(m -> m.jobId().equals(state.jobId()))
                    .map(CommitStore.CommitMeta::commitId).findFirst().orElse(null);
        }
        jobViews.put(key, new JobView(state.jobId(), JobStatus.COMMITTED, commitId, null));
        writeJob(ctx, new JobState(state.jobId(), JobStatus.COMMITTED.name(), state.rules(),
                state.files(), commitId, null));
    }

    // -------------------------------------------------------------- query

    public JobView jobStatus(String project, String jobId) {
        validateProject(project);
        JobView view = jobViews.get(jobKey(project, jobId));
        if (view != null) {
            return view;
        }
        JobState state = readJob(context(project), jobId);
        if (state == null) {
            return new JobView(jobId, null, null, "unknown job");
        }
        return new JobView(state.jobId(), JobStatus.valueOf(state.status()), state.commitId(), state.error());
    }

    /** Latest committed findings with exemptions applied. Never observes partial state. */
    public FindingsView currentFindings(String project) {
        validateProject(project);
        ProjectContext ctx = context(project);
        Optional<CommitStore.Commit> head = ctx.commits().head();
        if (head.isEmpty()) {
            return new FindingsView(null, null, List.of(), List.of(), Set.of(),
                    List.of(), List.of(), List.of(), 0, 0, 0, 0, 0);
        }
        return toView(ctx, head.get());
    }

    public FindingsView commitFindings(String project, String commitId) {
        validateProject(project);
        ProjectContext ctx = context(project);
        return ctx.commits().load(commitId).map(c -> toView(ctx, c)).orElse(null);
    }

    private FindingsView toView(ProjectContext ctx, CommitStore.Commit commit) {
        String rulesHash = commit.result().rulesHash();
        Set<String> suppressed = new LinkedHashSet<>();
        for (ExemptionStore.Exemption e : ctx.exemptions().activeFor(rulesHash, Instant.now())) {
            suppressed.add(e.fingerprint());
        }
        return new FindingsView(commit.meta().commitId(), rulesHash, commit.result().findings(),
                commit.result().removedFingerprints(), suppressed,
                commit.result().removedFiles(), commit.result().addedFiles(),
                commit.result().parseFailures(),
                commit.result().stats().reusedFiles(), commit.result().stats().reparsedFiles(),
                commit.result().stats().unchangedFiles(), commit.result().stats().failedFiles(),
                commit.result().stats().totalFiles());
    }

    public Optional<AnalysisResult> commitResult(String project, String commitId) {
        validateProject(project);
        return context(project).commits().load(commitId).map(CommitStore.Commit::result);
    }

    public List<CommitStore.CommitMeta> commits(String project) {
        validateProject(project);
        return context(project).commits().list();
    }

    // ---------------------------------------------------------- exemptions

    public ExemptionStore.Exemption exempt(String project, String fingerprint, String reason,
                                           String createdBy, Instant expiresAt) {
        validateProject(project);
        ProjectContext ctx = context(project);
        String rulesHash = ctx.commits().head()
                .map(c -> c.result().rulesHash())
                .orElseThrow(() -> new IllegalStateException("no committed analysis yet"));
        return ctx.exemptions().create(fingerprint, rulesHash, reason, createdBy, expiresAt);
    }

    public List<ExemptionStore.Exemption> exemptions(String project) {
        validateProject(project);
        return context(project).exemptions().list();
    }

    public Optional<ExemptionStore.Exemption> revokeExemption(String project, String id, String actor) {
        validateProject(project);
        return context(project).exemptions().revoke(id, actor);
    }

    public List<AuditLog.AuditEvent> audit(String project) {
        validateProject(project);
        return context(project).exemptions().auditLog().list();
    }

    // ------------------------------------------------------------ recovery

    /** Recover all projects after restart: drop partial writes, resume unfinished jobs. */
    public void recoverAll() {
        if (!Files.isDirectory(dataDir)) {
            return;
        }
        List<Path> projectDirs = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dataDir)) {
            for (Path p : stream) {
                if (Files.isDirectory(p)) {
                    projectDirs.add(p);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        for (Path dir : projectDirs) {
            String project = dir.getFileName().toString();
            ProjectContext ctx = context(project);
            ctx.commits().recover();
            Path jobsDir = dir.resolve("jobs");
            if (!Files.isDirectory(jobsDir)) {
                continue;
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(jobsDir, "*.json")) {
                for (Path jobFile : stream) {
                    JobState state = MAPPER.readValue(jobFile.toFile(), JobState.class);
                    recoverJob(ctx, project, state);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    private void recoverJob(ProjectContext ctx, String project, JobState state) {
        String key = jobKey(project, state.jobId());
        if (ctx.commits().hasCommitForJob(state.jobId())) {
            // Commit already exists: never re-analyze, just reflect the state.
            markCommitted(ctx, key, state);
            return;
        }
        if (JobStatus.COMMITTED.name().equals(state.status())) {
            // Job file claims committed but no commit exists: fall through and re-run
            // from the last committed position; the commit id is deterministic.
            jobViews.put(key, new JobView(state.jobId(), JobStatus.PENDING, null, null));
            executor.submit(() -> execute(ctx, project,
                    new JobState(state.jobId(), JobStatus.PENDING.name(), state.rules(), state.files(), null, null)));
            return;
        }
        if (JobStatus.FAILED.name().equals(state.status())) {
            jobViews.put(key, new JobView(state.jobId(), JobStatus.FAILED, null, state.error()));
            return;
        }
        // PENDING or RUNNING at crash time: resume from last committed position.
        jobViews.put(key, new JobView(state.jobId(), JobStatus.PENDING, null, null));
        executor.submit(() -> execute(ctx, project, state));
    }

    public void shutdown() {
        executor.shutdown();
        try {
            executor.awaitTermination(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------- helpers

    private ProjectContext context(String project) {
        return projects.computeIfAbsent(project, name -> {
            Path dir = dataDir.resolve(name);
            return new ProjectContext(dir, new CommitStore(dir), new ExemptionStore(dir));
        });
    }

    private static String jobKey(String project, String jobId) {
        return project + "/" + jobId;
    }

    private static void validateProject(String project) {
        if (project == null || !PROJECT_NAME.matcher(project).matches()) {
            throw new IllegalArgumentException("invalid project name: " + project);
        }
    }

    private void writeJob(ProjectContext ctx, JobState state) {
        try {
            Path jobsDir = ctx.dir().resolve("jobs");
            Files.createDirectories(jobsDir);
            Path tmp = jobsDir.resolve(state.jobId() + ".tmp");
            Files.writeString(tmp, MAPPER.writeValueAsString(state), StandardCharsets.UTF_8);
            Files.move(tmp, jobsDir.resolve(state.jobId() + ".json"),
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to persist job " + state.jobId(), e);
        }
    }

    private JobState readJob(ProjectContext ctx, String jobId) {
        Path file = ctx.dir().resolve("jobs").resolve(jobId + ".json");
        if (!Files.exists(file)) {
            return null;
        }
        try {
            return MAPPER.readValue(file.toFile(), JobState.class);
        } catch (IOException e) {
            return null;
        }
    }
}
