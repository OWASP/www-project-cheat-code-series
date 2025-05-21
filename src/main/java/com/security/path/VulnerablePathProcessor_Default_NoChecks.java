package com.security.path;

import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a vulnerable path processing implementation
 * that performs no validation or sanitization.
 */
public class VulnerablePathProcessor_Default_NoChecks extends PathProcessor {
    
    public VulnerablePathProcessor_Default_NoChecks(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public boolean isValidFilePath(String path, ValidationErrorList errors) {
        // Vulnerable: No validation
        return true;
    }

    @Override
    public String getSanitizedFilePath(String path) throws org.owasp.esapi.errors.ValidationException {
        // Vulnerable: No sanitization
        return path;
    }
} 