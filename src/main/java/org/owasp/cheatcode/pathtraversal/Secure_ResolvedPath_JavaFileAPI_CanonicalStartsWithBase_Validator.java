package org.owasp.cheatcode.pathtraversal;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses canonical path comparison to ensure paths are relative to a base directory.
 * It prevents directory traversal attacks by validating that paths don't escape the base directory.
 */
public class SecurePathProcessor_RelativeToBaseFolder_Validation extends PathProcessor {

    public SecurePathProcessor_RelativeToBaseFolder_Validation(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        File baseDir = new File(this.baseDirectory);
        File file = new File(baseDir, userInput);

        String destCanonicalPath;
        String fileCanonicalPath;

        try {
            destCanonicalPath = baseDir.getCanonicalPath();
            fileCanonicalPath = file.getCanonicalPath();
        } catch (IOException e) {
            throw new SecurityException("Path could not be canonicalised: " + userInput, e);
        }

        // Resolve first, then ask whether the answer is still inside the boundary. Nothing here
        // enumerates dangerous characters, so how the payload spells its traversal stops
        // mattering - there is no list of separators or escapes to keep complete.
        if (!fileCanonicalPath.startsWith(destCanonicalPath + File.separator)) {
            throw new SecurityException("Path escapes the base directory: " + userInput);
        }

        return readFrom(Paths.get(baseDirectory, userInput));
    }
}
