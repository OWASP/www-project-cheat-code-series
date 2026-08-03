package org.owasp.cheatcode.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The one thing every path traversal implementation here has in common: it is handed a string
 * that came from a user, and is expected to return the contents of a file.
 *
 * <p>This class contains no defence of its own, deliberately. It exists to run
 * {@link #getResource(String)} and write down what happened, so that a reader can open any single
 * implementation and see the whole technique in one method - the check, the repair if there is
 * one, the join, and the read - without reassembling it from a base-class pipeline.
 *
 * <p>Not thread-safe: one {@link #readFile(String)} call at a time per instance. The test harness
 * creates a fresh processor per test and the console demo is single-threaded.
 */
public abstract class PathProcessor {

    /**
     * The directory this processor is allowed to serve files from.
     */
    protected final String baseDirectory;

    /**
     * Where {@link #readFrom(Path)} last read from. Per-call state, reset by {@link #readFile}.
     */
    private Path resolvedPath;

    /**
     * Constructs a new PathProcessor with the specified base directory.
     *
     * @param baseDirectory The root directory that all paths will be relative to
     */
    protected PathProcessor(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    /**
     * Turns user input into file content: the whole technique this implementation demonstrates.
     *
     * <p>An implementation validates, repairs or refuses however it likes, then calls
     * {@link #readFrom(Path)} with the path it settled on. Refusing means throwing - the caller
     * gets an exception instead of content.
     *
     * <p>Called only with a non-null, non-empty input; {@link #readFile(String)} rejects those
     * first, so no implementation needs a guard for them.
     *
     * <p>Declared {@code throws Exception} so that all fourteen implementations share one
     * signature and differ only in their body - several of them throw ESAPI's checked
     * {@code ValidationException}, and narrowing per class would make the files harder to compare.
     *
     * @param userInput The untrusted string, exactly as received
     * @return The content of the file this implementation decided to serve
     * @throws Exception If the implementation refuses the input, or the read fails
     */
    public abstract String getResource(String userInput) throws Exception;

    /**
     * Reads the file the implementation settled on, and records which one that was.
     *
     * <p>The only sanctioned route to content. Reading around it - calling
     * {@code Files.readString} directly - leaves the report with no idea which file was served,
     * and the harness derives "was the input rewritten?" from exactly this path.
     *
     * @param resolved The path this implementation decided to read
     * @return The content of that file
     * @throws IOException If the file cannot be read
     */
    protected final String readFrom(Path resolved) throws IOException {
        this.resolvedPath = resolved;
        return Files.readString(resolved);
    }

    /**
     * Runs {@link #getResource(String)} and <em>reports</em> what happened rather than throwing.
     *
     * <p>Observing instead of propagating is the point: a processor that silently succeeds at an
     * attack has to be as visible as one that fails loudly, and a caller that only ever sees
     * exceptions cannot tell the two apart.
     *
     * @param userProvidedFileName The file name provided by the user
     * @return ReadFileResult recording the path resolved, the content read, and any exception
     */
    public final ReadFileResult readFile(String userProvidedFileName) {
        this.resolvedPath = null;

        ReadFileResult result = new ReadFileResult();
        result.baseDirectory = this.baseDirectory;
        result.userProvidedPath = userProvidedFileName;

        if (userProvidedFileName == null || userProvidedFileName.isEmpty()) {
            result.fileReadException =
                    new IllegalArgumentException("Input path cannot be null or empty");
            return result;
        }

        try {
            result.fileReadResult = getResource(userProvidedFileName);
        } catch (Exception e) {
            result.fileReadException = e;
        }

        result.resolvedPath = this.resolvedPath;
        return result;
    }
}
