package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Path;

/**
 * What happened when one string was handed to one {@link PathProcessor}.
 *
 * <p>Public mutable fields, deliberately: this is an observation record rather than a domain
 * object, and the harness reads it field by field to decide what a cell in the matrix means.
 *
 * <p>Nothing here claims the input was "detected" or "sanitised". Those were flags the old
 * base-class pipeline set on the implementation's behalf. An implementation now simply resolves a
 * path, and whether it rewrote the input on the way is <em>derived</em> by comparing
 * {@link #resolvedPath} against the naive join of {@link #baseDirectory} and
 * {@link #userProvidedPath} - so an implementation can neither claim a rewrite it did not perform
 * nor hide one it did.
 */
public class ReadFileResult {

    /**
     * The directory the processor was told it may serve files from.
     */
    public String baseDirectory;

    /**
     * The original string provided by the user, before any processing.
     */
    public String userProvidedPath;

    /**
     * The file the implementation actually decided to read, or null if it never got that far -
     * it refused the input, or the path could not be built at all.
     */
    public Path resolvedPath;

    /**
     * The content that was read, or null if nothing was.
     */
    public String fileReadResult;

    /**
     * Whatever the implementation threw, or null if it did not.
     */
    public Exception fileReadException;
}
