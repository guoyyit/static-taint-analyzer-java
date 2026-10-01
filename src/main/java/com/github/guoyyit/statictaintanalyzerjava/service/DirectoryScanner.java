package com.github.guoyyit.statictaintanalyzerjava.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.TreeMap;

/**
 * Recursively discovers readable source files under a submitted directory.
 *
 * <p>Map keys are logical, forward-slash paths relative to the scanned root so
 * incremental state is independent of where the project lives on disk and
 * stable across machines. Symlink loops and unreadable entries are skipped
 * rather than aborting the walk.
 */
public final class DirectoryScanner {

    /**
     * @param root       directory to scan (absolute or working-directory relative)
     * @param pathPrefix logical prefix prepended to each discovered key
     */
    public Map<String, String> scan(Path root, String pathPrefix) throws IOException {
        Path normalized = root.toAbsolutePath().normalize();
        if (!Files.isDirectory(normalized)) {
            throw new IOException("not a directory: " + root);
        }
        String prefix = pathPrefix == null || pathPrefix.isBlank() ? "" : trimPrefix(pathPrefix);
        Map<String, String> result = new TreeMap<>();
        Files.walkFileTree(normalized, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!attrs.isRegularFile()) {
                    return FileVisitResult.CONTINUE;
                }
                String name = file.getFileName().toString();
                if (!name.endsWith(".java")) {
                    return FileVisitResult.CONTINUE;
                }
                String relative = normalized.relativize(file).toString().replace('\\', '/');
                String key = prefix.isEmpty() ? relative : prefix + "/" + relative;
                try {
                    result.put(key, Files.readString(file, StandardCharsets.UTF_8));
                } catch (IOException | SecurityException readFailure) {
                    // Skip unreadable entries; other files remain analyzable.
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        return Map.copyOf(result);
    }

    private static String trimPrefix(String prefix) {
        String p = prefix.replace('\\', '/');
        while (p.startsWith("/")) {
            p = p.substring(1);
        }
        while (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        return p;
    }
}
