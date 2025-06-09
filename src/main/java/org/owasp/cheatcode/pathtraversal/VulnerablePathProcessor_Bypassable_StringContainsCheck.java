package org.owasp.cheatcode.pathtraversal;

import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a vulnerable path processing implementation
 * that performs only a simple string contains check.
 */
public class VulnerablePathProcessor_Bypassable_StringContainsCheck extends PathProcessor {
    
    public VulnerablePathProcessor_Bypassable_StringContainsCheck(String baseDirectory) {
        super(baseDirectory);
    }

    /**
     * Vulnerable method that only checks for "../" in the path
     * @param path The path to validate
     * @return false if path contains "../", true otherwise
     */
    @Override
    public boolean isValidFilePath(java.lang.String path, ValidationErrorList errors) {
        // Vulnerable: Only checks for "../" which can be bypassed
        return path != null && !path.contains("../");
    }

    /**
     * Vulnerable method that returns the input without any sanitization
     * @param path The path to sanitize
     * @return The original path without any sanitization
     */
    @Override
    public String getSanitizedFilePath(java.lang.String path) {
        // Vulnerable: Returns the input with bypassable sanitization
        return path.replace("../", "");
    }
} 