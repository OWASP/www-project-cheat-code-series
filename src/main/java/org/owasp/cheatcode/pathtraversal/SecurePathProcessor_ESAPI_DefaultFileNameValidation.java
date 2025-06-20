package org.owasp.cheatcode.pathtraversal;

import java.util.Arrays;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a secure path processing implementation
 * that uses OWASP ESAPI's file name validation.
 */
public class SecurePathProcessor_ESAPI_DefaultFileNameValidation extends PathProcessor {
    
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(
        "txt", "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif"
    );
    
    public SecurePathProcessor_ESAPI_DefaultFileNameValidation(String baseDirectory) {
        super(baseDirectory);
        // ESAPI is designed to throw exception on attack payload rather than sanitizing it in getValidFileName (while it still returns a canonicalized filename)
        //this.canSanitize = false;
    }

    
    
    /**
     * Method that validates a path using ESAPI's isValidFileName validator
     * @param path The path to validate
     * @return true if the path contains only a valid filename, false otherwise
     */
    @Override
    public boolean isValidFilePath(java.lang.String path, ValidationErrorList errors) {
        if (path == null) {
            return false;
        }
        // Use ESAPI's isValidFileName validator with allowNull=false
        return ESAPI.validator().isValidFileName("ESAPI FileName Validation", path, false, errors);
    }

    /**
     * Method that sanitizes a path by extracting only the filename component
     * and validating it with ESAPI
     * @param path The path to sanitize
     * @return The sanitized filename if valid, empty string otherwise
     */
    @Override
    public String getSanitizedFilePath(java.lang.String path) throws org.owasp.esapi.errors.ValidationException {
        if (path == null) {
            return "";
        }
        try {
            var sanitizedFileName = ESAPI.validator().getValidFileName("ESAPI FileName Validation", path, ALLOWED_EXTENSIONS, false);
            return sanitizedFileName;
        } catch (Exception e) {
            throw new org.owasp.esapi.errors.ValidationException("Failed to sanitize path using ESAPI.getValidFileName()", e.getMessage(), e);
        }
    }
} 