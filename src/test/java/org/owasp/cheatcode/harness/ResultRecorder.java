package org.owasp.cheatcode.harness;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Writes one JSON file per cell under {@code target/cheatcode-results/&lt;platform&gt;/}.
 *
 * <p>One file per cell rather than one file per run, so that concurrent test classes never
 * contend for a single output file, and so that results from several platforms merge by being
 * copied into the same tree.
 *
 * <p>The platform directory is cleared once per JVM, which means a full {@code mvn test} always
 * produces a clean set. Running a subset ({@code -Dtest=…}) therefore leaves only that subset
 * on disk — the report generator reports how many cells it read so a partial run is visible.
 */
public final class ResultRecorder {

    private static final Path ROOT = Paths.get(
            System.getProperty("cheatcode.results.dir", "target/cheatcode-results"));

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .disableHtmlEscaping()
            .create();

    private static final Set<Path> CLEARED = ConcurrentHashMap.newKeySet();

    private ResultRecorder() {
    }

    /**
     * Records one cell. Never throws in a way that would mask a test result — a reporting
     * failure is logged and swallowed, because losing the report is much less bad than
     * turning every test red when the disk is full.
     */
    public static void record(CellResult cell) {
        try {
            Path dir = ROOT.resolve(cell.platform);
            clearOnce(dir);
            Files.createDirectories(dir);

            Path file = dir.resolve(cell.implementation + "__" + cell.payloadId + ".json");
            try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                GSON.toJson(cell, writer);
            }
        } catch (Exception e) {
            System.err.println("[cheatcode] failed to record "
                    + cell.implementation + "/" + cell.payloadId + ": " + e);
        }
    }

    private static void clearOnce(Path dir) throws IOException {
        if (!CLEARED.add(dir) || !Files.isDirectory(dir)) {
            return;
        }
        try (var paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder())
                 .filter(p -> !p.equals(dir))
                 .forEach(p -> {
                     try {
                         Files.delete(p);
                     } catch (IOException e) {
                         throw new UncheckedIOException(e);
                     }
                 });
        }
    }
}
