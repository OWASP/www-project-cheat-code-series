package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Path;

/**
 * Result wrapper class for file operations that contains information about
 * the path processing and file reading results, including any validation,
 * sanitization, or error states that occurred during processing.
 */
public class ReadFileResult {
    /**
     * Indicates whether a path traversal attack was detected during path processing.
     * True if a potential path traversal attack was detected, false otherwise.
     */
    public boolean isPathTraversalAttackDetected = false;

    /**
     * Indicates whether the path was sanitized during processing.
     * True if the path was sanitized, false if it was either valid or sanitization failed.
     */
    public boolean isPathSanitized = false;

    /**
     * The original path provided by the user before any processing.
     */
    public String userProvidedPath;

    /**
     * The final processed path that was used to read the file.
     * This path has been validated and optionally sanitized.
     */
    public Path sanitizedFilePathToReadFrom;

    /**
     * The content of the file that was read.
     * Null if the file could not be read or if an error occurred.
     */
    public String fileReadResult;

    /**
     * Any exception that occurred during path processing or file reading.
     * Null if no errors occurred.
     */
    public Exception fileReadException;
} 