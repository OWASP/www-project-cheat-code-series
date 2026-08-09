package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * This class contains a secure path processing implementation
 * that uses simple regex validation.
 */
public class SecurePathProcessor_RegexValidation_Blacklist_Simple extends PathProcessor {

    // Regex pattern for dangerous characters: .. or / or \
    private static final String DANGEROUS_CHARS_REGEX_PATTERN = "\\.\\.|[/\\\\]";

    public SecurePathProcessor_RegexValidation_Blacklist_Simple(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        String fileName = userInput;

        // The same pattern decides both questions, so the check and the repair cannot drift
        // apart. Compare with SecurePathProcessor_StringContains_Simple, which reaches the same
        // verdicts by spelling the rule out twice.
        if (Pattern.compile(DANGEROUS_CHARS_REGEX_PATTERN).matcher(fileName).find()) {
            fileName = fileName.replaceAll(DANGEROUS_CHARS_REGEX_PATTERN, "");
        }

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
