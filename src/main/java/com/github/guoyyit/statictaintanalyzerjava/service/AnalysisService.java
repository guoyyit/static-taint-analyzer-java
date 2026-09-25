package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.analysis.JavaModelBuilder;
import com.github.guoyyit.statictaintanalyzerjava.analysis.model.ProgramModel;
import com.github.guoyyit.statictaintanalyzerjava.domain.AnalysisSnapshot;
import com.github.guoyyit.statictaintanalyzerjava.domain.Finding;
import com.github.guoyyit.statictaintanalyzerjava.domain.RiskLevel;
import com.github.guoyyit.statictaintanalyzerjava.exemption.AuditLog;
import com.github.guoyyit.statictaintanalyzerjava.exemption.ExemptionService;
import com.github.guoyyit.statictaintanalyzerjava.incremental.IncrementalAnalyzer;
import com.github.guoyyit.statictaintanalyzerjava.rules.RuleService;
import com.github.guoyyit.statictaintanalyzerjava.store.JobRecord;
import com.github.guoyyit.statictaintanalyzerjava.store.JsonStore;
import com.github.guoyyit.statictaintanalyzerjava.store.SnapshotStore;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Orchestrates analysis jobs. Jobs run on a single background thread; each job
 * produces one immutable snapshot that is committed atomically, so concurrent
 * readers only ever see complete results. A durable journal plus atomic file
 * commits give crash recovery: interrupted jobs are re-executed from the last
 * committed snapshot, never duplicated, never half-written.
 */
public class AnalysisService {

    /** Thrown by the test crash hook; never caught, simulating a hard crash. */
    public static final class SimulatedCrashException extends RuntimeException {
        public SimulatedCrashException(String message) {
            super(message);
        }
    }

    private final SnapshotStore store;
    private final JsonStore json;
    private final RuleService ruleService;
    private final ExemptionService exemptionService;
    private final AuditLog auditLog;
    private final IncrementalAnalyzer incrementalAnalyzer;
    private final ExecutorService executor;
    private final Map<String, Future<?>> inFlight = new LinkedHashMap<>();
    private final Path dataDir;

    /** Test hook invoked right before the atomic commit. */
    private volatile Runnable beforeCommitHook = () -> {
    };

    public AnalysisService(Path dataDir) {
        this(dataDir, Instant::now);
    }

    /** Test-friendly constructor with an injectable clock for exemption expiry. */
    public AnalysisService(Path dataDir, java.util.function.Supplier<Instant> clock) {
        this.dataDir = dataDir;
        this.json = new JsonStore();
        this.store = new SnapshotStore(dataDir, json);
        this.auditLog = new AuditLog(dataDir, json);
        this.ruleService = new RuleService(dataDir, json, auditLog).init();
        this.exemptionService = new ExemptionService(dataDir, json, auditLog, clock);
        this.incrementalAnalyzer = new IncrementalAnalyzer(json);
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "analysis-worker");
            t.setDaemon(true);
            return t;
        });
    }

    // ------------------------------------------------------------------
    // Jobs
    // ------------------------------------------------------------------

    /** Submits an asynchronous analysis of {@code sourceDir}; returns the job id. */
    public String submit(String sourceDir) {
        String jobId = UUID.randomUUID().toString();
        JobRecord job = JobRecord.pending(jobId, sourceDir, ruleService.current().hash(), Instant.now());
        store.writeJob(job);
        synchronized (inFlight) {
            inFlight.put(jobId, executor.submit(() -> runJob(jobId)));
        }
        return jobId;
    }

    /** Submits and blocks until the job finishes; rethrows crash/failure causes. */
    public JobRecord submitAndWait(String sourceDir) {
        String jobId = submit(sourceDir);
        await(jobId);
        return job(jobId).orElseThrow();
    }

    public void await(String jobId) {
        Future<?> future;
        synchronized (inFlight) {
            future = inFlight.get(jobId);
        }
        if (future != null) {
            try {
                future.get(60, TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new IllegalStateException("job " + jobId + " did not complete cleanly", e);
            }
        }
    }

    public Optional<JobRecord> job(String jobId) {
        return store.readJob(jobId);
    }

    public List<JobRecord> jobs() {
        return store.allJobs();
    }

    /**
     * Crash recovery: reload the last committed snapshot and re-execute every
     * interrupted job from it. Idempotent; safe to call repeatedly.
     */
    public synchronized void recover() {
        store.recover();
        for (JobRecord job : store.jobsNeedingRecovery()) {
            runJob(job.jobId());
        }
    }

    private void runJob(String jobId) {
        JobRecord job = store.readJob(jobId).orElseThrow();
        store.writeJob(job.withState(JobRecord.State.RUNNING, job.snapshotVersion(), "", Instant.now()));
        try {
            AnalysisSnapshot committed = execute(job);
            store.writeJob(job.withState(JobRecord.State.COMMITTED, committed.version(), "", Instant.now()));
        } catch (SimulatedCrashException e) {
            throw e; // hard crash: journal stays RUNNING for recovery
        } catch (Exception e) {
            store.writeJob(job.withState(JobRecord.State.FAILED, job.snapshotVersion(),
                    String.valueOf(e.getMessage()), Instant.now()));
            throw e instanceof RuntimeException re ? re : new RuntimeException(e);
        }
    }

    private AnalysisSnapshot execute(JobRecord job) {
        RuleService rules = this.ruleService;
        Map<String, String> sources = readSources(Path.of(job.sourceDir()));
        Map<String, String> hashes = new TreeMap<>();
        sources.forEach((path, content) -> hashes.put(path, Finding.sha256(content)));

        ProgramModel model = new JavaModelBuilder().buildFromStrings(sources);
        AnalysisSnapshot prior = store.current();
        long newVersion = prior.version() + 1;

        IncrementalAnalyzer.Outcome outcome = incrementalAnalyzer.analyze(
                model, hashes, rules.current(), prior, prior.findings(), newVersion);

        beforeCommitHook.run(); // crash point: nothing durable written yet for this job

        store.commit(outcome.snapshot());
        long newCount = outcome.diff().values().stream().filter(s -> s == IncrementalAnalyzer.Status.NEW).count();
        long removed = outcome.diff().values().stream().filter(s -> s == IncrementalAnalyzer.Status.REMOVED).count();
        auditLog.record("ANALYSIS_COMMITTED", "system",
                "job=" + job.jobId() + " version=" + newVersion + " findings="
                        + outcome.snapshot().findings().size() + " new=" + newCount + " removed=" + removed);
        return outcome.snapshot();
    }

    // ------------------------------------------------------------------
    // Queries (always served from the last committed snapshot)
    // ------------------------------------------------------------------

    public AnalysisSnapshot currentSnapshot() {
        return store.current();
    }

    /** Findings sorted by risk (desc) then fingerprint; exempted ones excluded by default. */
    public List<Finding> queryFindings(RiskLevel minRisk, boolean includeExempted) {
        List<Finding> all = store.current().findings();
        if (!includeExempted) {
            all = exemptionService.filterActive(all);
        }
        if (minRisk != null) {
            all = all.stream().filter(f -> f.risk().weight() >= minRisk.weight()).toList();
        }
        return all;
    }

    public Optional<Finding> finding(String fingerprint) {
        return store.current().findings().stream()
                .filter(f -> f.fingerprint().equals(fingerprint))
                .findFirst();
    }

    // ------------------------------------------------------------------
    // Baseline
    // ------------------------------------------------------------------

    /** Marks the current snapshot version as the baseline for "new findings" queries. */
    public synchronized void markBaseline(String actor) {
        long version = store.current().version();
        json.writeAtomic(dataDir().resolve("baseline.json"), new BaselinePointer(version));
        auditLog.record("BASELINE_MARKED", actor, "version=" + version);
    }

    /** Findings first seen after the baseline version. */
    public List<Finding> findingsNewSinceBaseline() {
        long baseline = json.read(dataDir().resolve("baseline.json"), BaselinePointer.class)
                .map(BaselinePointer::version).orElse(0L);
        return store.current().findings().stream()
                .filter(f -> f.firstSeenVersion() > baseline)
                .sorted(Comparator.naturalOrder())
                .toList();
    }

    // ------------------------------------------------------------------
    // Accessories
    // ------------------------------------------------------------------

    public RuleService ruleService() {
        return ruleService;
    }

    public ExemptionService exemptionService() {
        return exemptionService;
    }

    public AuditLog auditLog() {
        return auditLog;
    }

    public void setBeforeCommitHook(Runnable hook) {
        this.beforeCommitHook = hook == null ? () -> {
        } : hook;
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    private Path dataDir() {
        return dataDir;
    }

    private Map<String, String> readSources(Path sourceDir) {
        Map<String, String> sources = new TreeMap<>();
        try (Stream<Path> walk = Files.walk(sourceDir)) {
            List<Path> files = walk.filter(p -> p.toString().endsWith(".java"))
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
            for (Path file : files) {
                sources.put(sourceDir.relativize(file).toString(), Files.readString(file));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return sources;
    }

    private record BaselinePointer(
            @com.fasterxml.jackson.annotation.JsonProperty("version") long version) {
        @com.fasterxml.jackson.annotation.JsonCreator
        BaselinePointer {
        }
    }
}
