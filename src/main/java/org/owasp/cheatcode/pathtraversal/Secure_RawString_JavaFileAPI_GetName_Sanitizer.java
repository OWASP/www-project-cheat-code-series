package org.owasp.cheatcode.pathtraversal;

import java.io.File;
import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses Java's built-in file name APIs for sanitization.
 */
public class SecurePathProcessor_FileAPI_GetName extends PathProcessor {

    public SecurePathProcessor_FileAPI_GetName(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // File.getName() keeps only the last path element, so any directory part - hostile or
        // legitimate - is discarded. There is nothing to check first: the reduction always
        // applies, which is why this blocks every traversal payload and loses `SomeSubFolder/`
        // along with them. One line, no pattern to keep up to date, and no way to bypass it by
        // finding a separator the author did not think of.
        String fileName = new File(userInput).getName();

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
