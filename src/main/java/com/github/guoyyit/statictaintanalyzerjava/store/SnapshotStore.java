package com.github.guoyyit.statictaintanalyzerjava.store;

import com.github.guoyyit.statictaintanalyzerjava.domain.AnalysisSnapshot;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

/**
 * MVCC-style snapshot store. Writers stage a complete snapshot and commit it
 * atomically (snapshot file first, then the {@code current.json} pointer, then
 * the job journal); readers only ever load the pointer, so they always observe
 * one fully committed snapshot and never a half-written one.
 */
public final class SnapshotStore {

    private final JsonStore json;
    private final Path dir;
    private final ReentrantLock commitLock = new ReentrantLock();
    private final AtomicReference<AnalysisSnapshot> current = new AtomicReference<>(AnalysisSnapshot.empty());

    public SnapshotStore(Path dataDir) {
        this(dataDir, new JsonStore());
    }

    public SnapshotStore(Path dataDir, JsonStore json) {
        this.dir = dataDir;
        this.json = json;
    }

    /** Current committed snapshot; never null, always complete. */
    public AnalysisSnapshot current() {
        return current.get();
    }

    /**
     * Atomically publishes {@code snapshot}. The in-memory pointer is swapped
     * only after the durable commit completes.
     */
    public void commit(AnalysisSnapshot snapshot) {
        commitLock.lock();
        try {
            json.writeAtomic(snapshotFile(snapshot.version()), snapshot);
            json.writeAtomic(dir.resolve("current.json"), new CurrentPointer(snapshot.version()));
            current.set(snapshot);
        } finally {
            commitLock.unlock();
        }
    }

    /** Loads the last committed snapshot from disk; called once at startup/recovery. */
    public AnalysisSnapshot recover() {
        Optional<CurrentPointer> pointer = json.read(dir.resolve("current.json"), CurrentPointer.class);
        if (pointer.isEmpty()) {
            current.set(AnalysisSnapshot.empty());
            return current.get();
        }
        AnalysisSnapshot snapshot = json.read(snapshotFile(pointer.get().version()), AnalysisSnapshot.class)
                .orElse(AnalysisSnapshot.empty());
        current.set(snapshot);
        return snapshot;
    }

    // ------------------------------------------------------------------
    // Job journal
    // ------------------------------------------------------------------

    public void writeJob(JobRecord job) {
        json.writeAtomic(jobFile(job.jobId()), job);
    }

    public Optional<JobRecord> readJob(String jobId) {
        return json.read(jobFile(jobId), JobRecord.class);
    }

    /** All journal entries that were interrupted before completion. */
    public List<JobRecord> jobsNeedingRecovery() {
        List<JobRecord> out = new ArrayList<>();
        Path jobsDir = dir.resolve("jobs");
        if (!Files.isDirectory(jobsDir)) {
            return out;
        }
        try (Stream<Path> files = Files.list(jobsDir)) {
            files.filter(f -> f.getFileName().toString().endsWith(".json"))
                    .sorted(Comparator.comparing(f -> f.getFileName().toString()))
                    .forEach(f -> json.read(f, JobRecord.class)
                            .filter(JobRecord::needsRecovery)
                            .ifPresent(out::add));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    public List<JobRecord> allJobs() {
        List<JobRecord> out = new ArrayList<>();
        Path jobsDir = dir.resolve("jobs");
        if (!Files.isDirectory(jobsDir)) {
            return out;
        }
        try (Stream<Path> files = Files.list(jobsDir)) {
            files.filter(f -> f.getFileName().toString().endsWith(".json"))
                    .sorted(Comparator.comparing(f -> f.getFileName().toString()))
                    .forEach(f -> json.read(f, JobRecord.class).ifPresent(out::add));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    private Path snapshotFile(long version) {
        return dir.resolve("snapshots").resolve("snapshot-" + version + ".json");
    }

    private Path jobFile(String jobId) {
        return dir.resolve("jobs").resolve("job-" + jobId + ".json");
    }

    /** Commit pointer; written last so readers never see a partial snapshot. */
    public record CurrentPointer(@com.fasterxml.jackson.annotation.JsonProperty("version") long version) {
        @com.fasterxml.jackson.annotation.JsonCreator
        public CurrentPointer {
        }
    }
}
