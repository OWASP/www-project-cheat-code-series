package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * Vulnerable. Deletes every literal {@code ../} from the input and reads whatever is left.
 *
 * <p>The sanitizer half of a matched pair. Its twin,
 * {@link Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator}, applies the identical
 * rule - "this input involves {@code ../}" - and reaches the opposite result on
 * {@code ....//....//pwnStorage//secret.txt}: the validator refuses that payload, this one
 * manufactures a working traversal out of it. Same rule, same payload, opposite outcome. The
 * difference is not the rule but what the code does once the rule has spoken.
 *
 * <p>Known bypasses:
 * <ul>
 *   <li>{@code ....//....//} - deleting {@code ../} splices the surrounding characters into a
 *       fresh {@code ../}. Deleting a substring cannot be a defence when deleting it can also
 *       create it.</li>
 *   <li>{@code ..\..\} - the rule names a forward slash, so a backslash-separated traversal is
 *       not touched at all, on the platform where backslash is a separator.</li>
 * </ul>
 */
public class Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer extends PathProcessor {

    public Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Vulnerable: repair by deletion, applied unconditionally because that is what a
        // sanitizer is - it does not ask a question, it rewrites. (Guarding this with
        // `if (contains("../"))` changes nothing: deleting a substring that is not there
        // returns the same string. The guard only ever made the class look like it validated.)
        //
        // Deleting `../` out of `....//` splices what surrounds it back together into a fresh
        // `../`, so a payload that contained no usable traversal leaves this method containing
        // one. The repair builds the attack.
        String fileName = userInput.replace("../", "");

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
