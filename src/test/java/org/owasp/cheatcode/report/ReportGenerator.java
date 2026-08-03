package org.owasp.cheatcode.report;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.google.gson.Gson;

import org.owasp.cheatcode.harness.CellResult;

/**
 * Builds the human-readable matrix from the JSON emitted by the last test run.
 *
 * <pre>
 * mvn clean test
 * mvn exec:java@report
 * </pre>
 *
 * <p>Produces {@code target/report/index.html} — the artifact meant to be read — and
 * {@code target/report/results-table.md}, which is pasted into the README. Both come from the
 * same recorded cells, so the published table cannot drift from what the code actually does.
 *
 * <p>Reads every platform directory it finds, so results gathered on several machines merge by
 * being copied into one {@code cheatcode-results} tree before this runs.
 */
public final class ReportGenerator {

    private static final Gson GSON = new Gson();

    private ReportGenerator() {
    }

    public static void main(String[] args) throws IOException {
        Path resultsDir = Paths.get(args.length > 0 ? args[0]
                : System.getProperty("cheatcode.results.dir", "target/cheatcode-results"));
        Path outputDir = Paths.get(args.length > 1 ? args[1]
                : System.getProperty("cheatcode.report.dir", "target/report"));

        if (!Files.isDirectory(resultsDir)) {
            System.err.println("No results at " + resultsDir.toAbsolutePath()
                    + " - run `mvn test` first.");
            System.exit(1);
        }

        List<CellResult> cells = load(resultsDir);
        if (cells.isEmpty()) {
            System.err.println("No cells found under " + resultsDir.toAbsolutePath());
            System.exit(1);
        }

        Files.createDirectories(outputDir);
        Path html = outputDir.resolve("index.html");
        Path markdown = outputDir.resolve("results-table.md");
        Files.writeString(html, new HtmlReport(cells).render(), StandardCharsets.UTF_8);
        Files.writeString(markdown, new MarkdownReport(cells).render(), StandardCharsets.UTF_8);

        summarise(cells, html, markdown);
    }

    private static List<CellResult> load(Path resultsDir) throws IOException {
        List<CellResult> cells = new ArrayList<>();
        try (var paths = Files.walk(resultsDir)) {
            List<Path> files = paths.filter(Files::isRegularFile)
                                    .filter(p -> p.getFileName().toString().endsWith(".json"))
                                    .sorted()
                                    .collect(Collectors.toList());
            for (Path file : files) {
                try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    CellResult cell = GSON.fromJson(reader, CellResult.class);
                    if (cell != null) {
                        cells.add(cell);
                    }
                } catch (Exception e) {
                    System.err.println("Skipping unreadable " + file + ": " + e);
                }
            }
        }
        return cells;
    }

    /**
     * Reports what was actually read, so that a report built from a partial run
     * ({@code mvn test -Dtest=...}) is obvious rather than quietly looking complete.
     */
    private static void summarise(List<CellResult> cells, Path html, Path markdown) {
        Set<String> platforms = new TreeSet<>();
        Set<String> implementations = new TreeSet<>();
        Map<String, Integer> byStatus = new LinkedHashMap<>();
        Map<String, Integer> byVerdict = new LinkedHashMap<>();
        for (CellResult cell : cells) {
            platforms.add(cell.platform);
            implementations.add(cell.implementation);
            byStatus.merge(cell.status, 1, Integer::sum);
            byVerdict.merge(cell.verdict, 1, Integer::sum);
        }

        System.out.println("Read " + cells.size() + " cells"
                + " / " + implementations.size() + " implementations"
                + " / platforms " + platforms);
        System.out.println("  status  " + byStatus);
        System.out.println("  verdict " + byVerdict);

        int undeclared = byStatus.getOrDefault(CellResult.UNDECLARED, 0);
        int mismatched = byStatus.getOrDefault(CellResult.MISMATCH, 0);
        if (undeclared > 0 || mismatched > 0) {
            System.out.println("  NOTE: " + mismatched + " mismatched and " + undeclared
                    + " undeclared cells are in this report. It does not describe a green run.");
        }

        System.out.println("Wrote " + html.toAbsolutePath());
        System.out.println("Wrote " + markdown.toAbsolutePath());
    }

    // -- shared presentation vocabulary --------------------------------------

    /**
     * Short code used in a table cell, where a full outcome name will not fit.
     *
     * <p>Codes are neutral about whether the outcome is good, because the same outcome means
     * opposite things in different columns: {@code rewritten} against an attack is a block,
     * {@code rewritten} against legitimate input is broken functionality. The colour carries
     * that judgement; the code just says what happened.
     *
     * <p>The two codes that mean "the implementation is not what protected you" are capitalised,
     * so they stand out even in a monochrome copy of the table.
     */
    static String shortCode(String outcome) {
        if (outcome == null) {
            return "-";
        }
        switch (outcome) {
            case "READ_OK":             return "ok";
            case "SANITIZED_HIT":       return "ok*";
            case "REJECTED":            return "refused";
            case "SANITIZE_FAILED":     return "threw";
            case "SANITIZED_MISS":      return "rewritten";
            case "UNDETECTED_MISS":     return "MISS";
            case "REJECTED_BY_RUNTIME": return "jdk";
            case "SECRET_DISCLOSED":    return "BREACH";
            case "READ_UNEXPECTED":     return "?";
            default:                    return "ERR";
        }
    }

    /**
     * Strips the {@code {Vulnerable|Secure}PathProcessor_} prefix, which every row carries and
     * which the group heading already states.
     */
    static String shortName(String implementation) {
        return implementation.replaceFirst("^(Vulnerable|Secure)_?PathProcessor_", "");
    }

    static String verdictDot(String verdict) {
        if (verdict == null) {
            return "⚪";
        }
        switch (verdict) {
            case "SAFE":               return "🟢";
            case "FUNCTIONALITY_LOST": return "🟠";
            case "NEAR_MISS":          return "🟡";
            case "BREACH":             return "🔴";
            default:                   return "🟣";
        }
    }

    /** One line on what an outcome means. Drives both the HTML legend and the markdown legend. */
    static String outcomeMeaning(String outcome) {
        switch (outcome) {
            case "READ_OK":
                return "Read succeeded and returned the content the payload legitimately asks for.";
            case "SANITIZED_HIT":
                return "Input was detected and repaired, and the repaired read succeeded safely.";
            case "REJECTED":
                return "Detected and refused outright - the implementation does not attempt repair.";
            case "SANITIZE_FAILED":
                return "Detected, repair attempted, and the repair itself threw. The caller gets an exception.";
            case "SANITIZED_MISS":
                return "Detected and repaired into a path that does not exist. Blocked - but legitimate "
                     + "input of the same shape is silently rewritten too.";
            case "UNDETECTED_MISS":
                return "NOT detected. The read failed only because of where the fixture puts its files. "
                     + "A near miss, not a defence.";
            case "REJECTED_BY_RUNTIME":
                return "The JDK or filesystem refused the path. The implementation contributed nothing, "
                     + "and would have no protection on a platform with laxer path parsing.";
            case "SECRET_DISCLOSED":
                return "The payload reached the secret.";
            case "READ_UNEXPECTED":
                return "A read succeeded but returned neither the expected content nor the secret.";
            default:
                return "Something the harness has no story for. Always worth looking at.";
        }
    }

    static String verdictMeaning(String verdict) {
        switch (verdict) {
            case "SAFE":               return "The implementation did the right thing.";
            case "FUNCTIONALITY_LOST": return "The attack is stopped, and so is legitimate input of the same shape.";
            case "NEAR_MISS":          return "The attack did not land, but the implementation is not why.";
            case "BREACH":             return "The payload reached the secret.";
            default:                   return "Unclassified.";
        }
    }

    // -- ordering ------------------------------------------------------------

    /**
     * Implementations worst-first within their group, so the report opens on what fails rather
     * than on what passes. Derived from the results themselves rather than from a hand-maintained
     * list, so a new implementation lands in the right place without anyone updating an ordering.
     */
    static Comparator<Map.Entry<String, List<CellResult>>> implementationOrder() {
        return Comparator
                .comparing((Map.Entry<String, List<CellResult>> e) ->
                        e.getValue().get(0).vulnerableByDesign ? 0 : 1)
                .thenComparing(e -> -count(e.getValue(), "BREACH"))
                .thenComparing(e -> -count(e.getValue(), "NEAR_MISS"))
                .thenComparing(e -> -count(e.getValue(), "FUNCTIONALITY_LOST"))
                .thenComparing(Map.Entry::getKey);
    }

    private static int count(List<CellResult> cells, String verdict) {
        int n = 0;
        for (CellResult cell : cells) {
            if (verdict.equals(cell.verdict)) {
                n++;
            }
        }
        return n;
    }

    /** Payload columns in the order they are declared in the enum. */
    static Comparator<CellResult> payloadOrder() {
        return Comparator.comparingInt((CellResult c) -> c.payloadOrdinal)
                         .thenComparing(c -> Objects.toString(c.payloadId, ""));
    }
}
