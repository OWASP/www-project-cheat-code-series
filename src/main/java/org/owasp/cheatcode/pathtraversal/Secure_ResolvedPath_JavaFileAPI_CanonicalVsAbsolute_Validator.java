package org.owasp.cheatcode.pathtraversal;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses canonical path comparison for path traversal detection.
 * Based on https://stackoverflow.com/questions/2375903/whats-the-best-way-to-defend-against-a-path-traversal-attack/34658355#34658355
 */
public class Secure_ResolvedPath_JavaFileAPI_CanonicalVsAbsolute_Validator extends PathProcessor {

    public Secure_ResolvedPath_JavaFileAPI_CanonicalVsAbsolute_Validator(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        File file = new File(userInput);

        // Check if the path is absolute
        if (file.isAbsolute()) {
            throw new SecurityException("Absolute paths are not accepted: " + userInput);
        }

        String canonicalPath;
        String absolutePath;

        try {
            canonicalPath = file.getCanonicalPath();
            absolutePath = file.getAbsolutePath();
        } catch (IOException e) {
            // getCanonicalPath refuses some inputs outright - an embedded NUL, for one. That is
            // this implementation detecting the payload, not the JDK's path parser doing it for
            // free later on, which is why this scores as a defence and not as a near miss.
            throw new SecurityException("Path could not be canonicalised: " + userInput, e);
        }

        // Canonicalising resolves `..` segments, so a path that changed under canonicalisation
        // was trying to go somewhere other than where it named.
        if (!canonicalPath.startsWith(absolutePath) && !canonicalPath.equals(absolutePath)) {
            throw new SecurityException("Path traversal detected: " + userInput);
        }

        // Refuses rather than repairs. There is no second attempt to get wrong, and the caller
        // gets an exception instead of the contents of a file they did not ask for - which is
        // also why this is one of only two implementations that still serves `SomeSubFolder/`.
        return readFrom(Paths.get(baseDirectory, userInput));
    }
}
