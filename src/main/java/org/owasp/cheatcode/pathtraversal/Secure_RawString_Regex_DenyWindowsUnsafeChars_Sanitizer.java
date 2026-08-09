package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses complex regex validation.
 */
public class Secure_RawString_Regex_DenyWindowsUnsafeChars_Sanitizer extends PathProcessor {

    //Matches invalid Windows filename characters (/ \ : * ? " < > |).
    //Matches leading whitespace.
    //Matches trailing whitespace or dot (.).
    private static final String DANGEROUS_CHARS_PATTERN = "([/\\\\:*?\"<>|])|(^\\s)|([.\\s]$)";

    public Secure_RawString_Regex_DenyWindowsUnsafeChars_Sanitizer(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Two rules, because the pattern does not cover NUL: an extended deny-list grows a
        // special case every time someone finds a character it forgot. Invalid characters
        // become an underscore; NUL is removed entirely, since an underscore would leave a
        // filename nobody asked for.
        //
        // Both applied unconditionally: this repairs input, it never refuses it, so there is
        // no question to ask first. The "is it already clean?" test this used to run ahead of
        // the repair could not change the outcome - it only made the class look like it
        // validated.
        String fileName = userInput
                .replaceAll(DANGEROUS_CHARS_PATTERN, "_")
                .replace("\0", "");

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
