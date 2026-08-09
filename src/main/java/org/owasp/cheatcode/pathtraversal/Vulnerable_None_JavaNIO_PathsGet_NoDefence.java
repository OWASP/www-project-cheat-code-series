package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization.
 */
public class VulnerablePathProcessor_Default_NoChecks extends PathProcessor {

    public VulnerablePathProcessor_Default_NoChecks(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Vulnerable: no validation, no sanitization. Whatever the caller sent is the path,
        // and Paths.get happily resolves `..` segments in it.
        return readFrom(Paths.get(baseDirectory, userInput));
    }
}
