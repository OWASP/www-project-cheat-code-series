package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * This class contains a secure path processing implementation
 * that uses whitelist regex validation to only allow alphanumeric characters.
 */
public class SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot extends PathProcessor {

    // Regex pattern that only allows alphanumeric characters
    private static final String WHITELIST_REGEX_PATTERN = "^[a-zA-Z0-9.]+$";

    public SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        String fileName = userInput;

        // Allow-list: state what is permitted and everything else is excluded by omission.
        // Note that no rule here mentions traversal, separators or NUL - none of them are
        // alphanumeric, so none of them need naming. That is the argument for allow-lists in
        // one line, and the reason this class needs no maintenance when a new payload appears.
        if (!Pattern.compile(WHITELIST_REGEX_PATTERN).matcher(fileName).matches()) {
            fileName = fileName.replaceAll("[^a-zA-Z0-9.]", "");
        }

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
