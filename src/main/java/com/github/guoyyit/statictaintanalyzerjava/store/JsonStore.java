package com.github.guoyyit.statictaintanalyzerjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

/**
 * JSON persistence with atomic writes: every write goes to a temp file followed
 * by an atomic move, so a crash can never leave a half-written file behind.
 */
public final class JsonStore {

    private final ObjectMapper mapper;

    public JsonStore() {
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    public ObjectMapper mapper() {
        return mapper;
    }

    /** Atomically replaces {@code target} with the serialized value. */
    public void writeAtomic(Path target, Object value) {
        try {
            Files.createDirectories(target.getParent());
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), value);
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> Optional<T> read(Path file, Class<T> type) {
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(file.toFile(), type));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
