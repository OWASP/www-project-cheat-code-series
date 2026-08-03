package org.owasp.cheatcode.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The directory layout every path traversal test runs against.
 *
 * <pre>
 * root/SecureStorage/baseWorkingDirectory/                  &lt;- base directory given to the processor
 * root/SecureStorage/baseWorkingDirectory/legit.txt
 * root/SecureStorage/baseWorkingDirectory/SomeSubFolder/sublegit.txt
 * root/pwnStorage/secret.txt                                &lt;- the prize
 * </pre>
 *
 * <p>The nesting is deliberate: the base directory sits <em>two</em> levels below the secret, so
 * a single {@code ../} lands one level short and only a double traversal reaches it. That is what
 * makes {@link org.owasp.cheatcode.harness.Outcome#UNDETECTED_MISS} observable — an implementation
 * can fail to detect a payload and still not disclose anything, and the matrix says so rather than
 * crediting it with a defence.
 *
 * <p>Extracted from the test base class so that a future container-based fixture can build the
 * same layout on a filesystem {@code @TempDir} cannot provide (symlinks, case-insensitive mounts).
 */
final class PathTraversalFixture {

    static final String PUBLIC_FILE_CONTENT = "Test file content";
    static final String SUBFOLDER_CONTENT = "Subfolder file content";
    static final String SECRET_FILE_CONTENT = "Attack succeeded! CONFIDENTIAL DATA disclosed!";

    private final Path baseDirectory;

    private PathTraversalFixture(Path baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    /**
     * Builds the layout under {@code root}.
     *
     * @param root an empty directory, normally a JUnit {@code @TempDir}
     * @return the fixture, whose {@link #baseDirectory()} is what the processor is given
     */
    static PathTraversalFixture create(Path root) throws IOException {
        Path baseDirectory = root.resolve("SecureStorage").resolve("baseWorkingDirectory");
        Files.createDirectories(baseDirectory);
        Files.writeString(baseDirectory.resolve("legit.txt"), PUBLIC_FILE_CONTENT);

        Path subfolder = baseDirectory.resolve("SomeSubFolder");
        Files.createDirectories(subfolder);
        Files.writeString(subfolder.resolve("sublegit.txt"), SUBFOLDER_CONTENT);

        Path pwnStorage = root.resolve("pwnStorage");
        Files.createDirectories(pwnStorage);
        Files.writeString(pwnStorage.resolve("secret.txt"), SECRET_FILE_CONTENT);

        return new PathTraversalFixture(baseDirectory);
    }

    /** The directory the processor is told it may serve files from. */
    Path baseDirectory() {
        return baseDirectory;
    }
}
