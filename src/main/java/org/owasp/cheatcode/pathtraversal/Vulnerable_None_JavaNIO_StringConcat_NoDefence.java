package org.owasp.cheatcode.pathtraversal;

import java.io.File;
import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization, and glues the path together from strings
 * instead of building it with Paths.get(base, input).
 *
 * <p>Kept alongside Vulnerable_None_JavaNIO_PathsGet_NoDefence to make a point by comparison:
 * the two differ only in the join, and they score identically on every payload. String
 * concatenation is a code smell here, not the vulnerability - the missing validation is.
 */
public class Vulnerable_None_JavaNIO_StringConcat_NoDefence extends PathProcessor {

    public Vulnerable_None_JavaNIO_StringConcat_NoDefence(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Vulnerable: no validation, and the path is concatenated rather than joined.
        // Paths.get(a, b) is specified as joining with the name separator and then parsing, so
        // for every payload in the matrix this produces the same Path as Paths.get(base, input).
        return readFrom(Paths.get(baseDirectory + File.separator + userInput));
    }
}
