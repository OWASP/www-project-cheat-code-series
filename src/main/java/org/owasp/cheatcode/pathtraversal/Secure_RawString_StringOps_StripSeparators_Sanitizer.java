package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses simple string validation.
 */
public class SecurePathProcessor_StringContains_Simple extends PathProcessor {

    public SecurePathProcessor_StringContains_Simple(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        String fileName = userInput;

        // Deny-list: anything that could name a directory is treated as hostile. That blocks
        // every traversal payload, and it also blocks `SomeSubFolder/sublegit.txt` - the cost
        // of reducing input to a bare filename, paid whether the caller was attacking or not.
        if (fileName.contains("..") || fileName.contains("/")
            || fileName.contains("\\")) {
            // Repaired rather than refused, which is the interesting part: the caller gets no
            // error, just the contents of a different file - or, as here, a NoSuchFileException
            // for a filename nobody asked for.
            fileName = fileName.replace("..", "")
                               .replace("/", "")
                               .replace("\\", "");
        }

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
