package com.github.guoyyit.statictaintanalyzerjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Append-only audit trail for exemptions, commits and rule changes.
 * One JSON object per line; entries are never modified or deleted.
 */
public final class AuditLog {

    public record AuditEvent(long seq, Instant at, String actor, String action, String detail) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private final Path logFile;
    private long nextSeq;

    public AuditLog(Path projectDir) {
        this.logFile = projectDir.resolve("audit.log");
        this.nextSeq = load().stream().mapToLong(AuditEvent::seq).max().orElse(0) + 1;
    }

    public synchronized void append(String actor, String action, String detail) {
        AuditEvent event = new AuditEvent(nextSeq++, Instant.now(), actor, action, detail);
        try {
            Files.createDirectories(logFile.getParent());
            Files.writeString(logFile, MAPPER.writeValueAsString(event) + "\n",
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to append audit event", e);
        }
    }

    public List<AuditEvent> list() {
        return load();
    }

    private List<AuditEvent> load() {
        List<AuditEvent> events = new ArrayList<>();
        if (!Files.exists(logFile)) {
            return events;
        }
        try {
            for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    events.add(MAPPER.readValue(line, AuditEvent.class));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read audit log", e);
        }
        return events;
    }
}
