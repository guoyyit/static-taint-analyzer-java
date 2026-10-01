package com.github.guoyyit.statictaintanalyzerjava.service;

import com.github.guoyyit.statictaintanalyzerjava.lang.ParseFailure;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Recursively discovers {@code .java} files under a server-side directory and
 * loads them into a map of {@code relative/path/Name.java -> content}.
 *
 * <p>Keys are always relative to the scanned root and use {@code /} separators,
 * so the same project scanned repeatedly yields stable, comparable paths and
 * deleted files naturally disappear from the map (the incremental engine then
 * lists them as removed).
 */
public final class DirectoryScanner {

    private DirectoryScanner() {
    }

    public record ScanResult(Map<String, String> files, List<ParseFailure> failures) {
    }

    public static Map<String, String> scanJava(String directory) {
        return scan(directory).files();
    }

    /**
     * Scans the directory; a read failure on one file is isolated and reported
     * (IO_ERROR with the file name) instead of aborting the whole project.
     * An unreadable/missing scan root itself throws IllegalArgumentException.
     */
    public static ScanResult scan(String directory) {
        if (directory == null || directory.isBlank()) {
            return new ScanResult(Map.of(), List.of());
        }
        Path root = Paths.get(directory).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            throw new IllegalArgumentException("not a readable directory: " + directory);
        }
        Map<String, String> files = new HashMap<>();
        List<ParseFailure> failures = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root)) {
            List<Path> javaFiles = new ArrayList<>();
            walk.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".java"))
                    .forEach(javaFiles::add);
            javaFiles.sort(Comparator.comparing(p -> root.relativize(p).toString()));
            for (Path file : javaFiles) {
                Path relative = root.relativize(file);
                if (relative.toString().contains("..")) {
                    continue; // defensive: never escape the scan root
                }
                String key = relative.toString().replace(java.io.File.separatorChar, '/');
                try {
                    files.put(key, Files.readString(file, StandardCharsets.UTF_8));
                } catch (IOException readError) {
                    failures.add(ParseFailure.io(key, readError.getClass().getSimpleName()
                            + ": " + readError.getMessage()));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to scan directory " + directory, e);
        }
        return new ScanResult(Map.copyOf(files), List.copyOf(failures));
    }
}
