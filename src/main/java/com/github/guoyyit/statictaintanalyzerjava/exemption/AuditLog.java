package com.github.guoyyit.statictaintanalyzerjava.exemption;

import com.github.guoyyit.statictaintanalyzerjava.domain.AuditEvent;
import com.github.guoyyit.statictaintanalyzerjava.store.JsonStore;

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
 * Append-only audit log (JSONL). Every exemption change, rule change and
 * analysis commit is recorded; the log is never rewritten, only appended.
 */
public final class AuditLog {

    private final JsonStore json;
    private final Path file;

    public AuditLog(Path dataDir, JsonStore json) {
        this.json = json;
        this.file = dataDir.resolve("audit.jsonl");
    }

    public synchronized void record(String type, String actor, String details) {
        record(new AuditEvent(Instant.now(), type, actor, details));
    }

    public synchronized void record(AuditEvent event) {
        try {
            Files.createDirectories(file.getParent());
            String line = json.mapper().writeValueAsString(event) + "\n";
            Files.writeString(file, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public List<AuditEvent> events() {
        List<AuditEvent> out = new ArrayList<>();
        if (!Files.exists(file)) {
            return out;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    out.add(json.mapper().readValue(line, AuditEvent.class));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }
}
