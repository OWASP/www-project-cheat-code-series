package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * Vulnerable. Refuses any input containing the literal {@code ../}, and reads the input
 * untouched when it does not.
 *
 * <p>The validator half of a matched pair. Its twin,
 * {@link Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer}, applies the identical
 * rule and differs only in what it does once the rule has spoken - refuse, or repair. That one
 * difference is worth a whole row of the matrix: on
 * {@code ....//....//pwnStorage//secret.txt} this class refuses and its twin discloses the
 * secret. The payload is built to survive a deletion, and there is nothing to survive here.
 *
 * <p>This is still {@code Vulnerable}, and by a payload alone: the rule names a forward slash,
 * so {@code ..\..\pwnStorage\secret.txt} contains no {@code ../}, passes the check untouched,
 * and traverses on the platform where backslash is a separator. Refusing instead of repairing
 * closes one bypass. It does not make an incomplete rule complete.
 *
 * <p>Known bypasses: {@code ..\..\} on Windows.
 */
public class Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator extends PathProcessor {

    public Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // The same rule the sanitizer twin applies, decided the other way: refuse, rather than
        // try to make the input acceptable. Nothing is rewritten, so there is no repair to turn
        // into an attack - `....//` contains a literal `../`, and that is the end of it.
        if (userInput.contains("../")) {
            throw new SecurityException("Path traversal detected: " + userInput);
        }

        // Vulnerable: what passes the check is read exactly as received. The check is the whole
        // defence, and it only knows one spelling of traversal.
        return readFrom(Paths.get(baseDirectory, userInput));
    }
}
