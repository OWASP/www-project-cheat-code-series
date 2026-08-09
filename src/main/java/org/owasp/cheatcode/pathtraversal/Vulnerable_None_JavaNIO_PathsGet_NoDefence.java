package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization.
 */
public class Vulnerable_None_JavaNIO_PathsGet_NoDefence extends PathProcessor {

    public Vulnerable_None_JavaNIO_PathsGet_NoDefence(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Vulnerable: no validation, no sanitization. Whatever the caller sent is the path,
        // and Paths.get happily resolves `..` segments in it.
        return readFrom(Paths.get(baseDirectory, userInput));
    }
}
