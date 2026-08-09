package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses simple regex validation.
 */
public class Secure_RawString_Regex_DenySeparators_Sanitizer extends PathProcessor {

    // Regex pattern for dangerous characters: .. or / or \
    private static final String DANGEROUS_CHARS_REGEX_PATTERN = "\\.\\.|[/\\\\]";

    public Secure_RawString_Regex_DenySeparators_Sanitizer(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // One pattern, stated once and applied unconditionally: this repairs input, it never
        // refuses it. The guarded shape this used to have - "if the pattern is present, remove
        // the pattern" - could not behave differently, because removing a pattern that is not
        // there returns the string unchanged.
        //
        // Note what the deny-list actually removes: every separator, not every `../`. That is
        // why Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer falls to `....//` and this
        // does not - with no separator left, there is nothing to traverse with. It also costs
        // `SomeSubFolder/sublegit.txt`, which is the same fact seen from the other side.
        String fileName = userInput.replaceAll(DANGEROUS_CHARS_REGEX_PATTERN, "");

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
