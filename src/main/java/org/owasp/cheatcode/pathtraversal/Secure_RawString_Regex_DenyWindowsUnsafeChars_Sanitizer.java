package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * This class contains a secure path processing implementation
 * that uses complex regex validation.
 */
public class SecurePathProcessor_RegexValidation_Blacklist_Extended extends PathProcessor {

    //Matches invalid Windows filename characters (/ \ : * ? " < > |).
    //Matches leading whitespace.
    //Matches trailing whitespace or dot (.).
    private static final String DANGEROUS_CHARS_PATTERN = "([/\\\\:*?\"<>|])|(^\\s)|([.\\s]$)";

    public SecurePathProcessor_RegexValidation_Blacklist_Extended(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        String fileName = userInput;

        // Two rules, because the pattern does not cover NUL: an extended deny-list grows a
        // special case every time someone finds a character it forgot.
        boolean valid = !Pattern.compile(DANGEROUS_CHARS_PATTERN).matcher(fileName).find()
                     && !fileName.contains("\0");

        if (!valid) {
            //Replace invalid characters with underscore and remove null characters (\0) entirely
            fileName = fileName.replaceAll(DANGEROUS_CHARS_PATTERN, "_").replaceAll("\0", "");
        }

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
