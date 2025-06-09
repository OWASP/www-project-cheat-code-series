package org.owasp.cheatcode.pathtraversal;

import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a secure path processing implementation
 * that uses simple regex validation.
 */
public class SecurePathProcessor_StringContains_Simple extends PathProcessor {
    
    public SecurePathProcessor_StringContains_Simple(String baseDirectory) {
        super(baseDirectory);
    } 
    
    /**
     * Method that validates a path by checking for dangerous characters
     * @param path The path to validate
     * @return true if the path is valid, false otherwise
     */
    @Override
    public boolean isValidFilePath(java.lang.String path, ValidationErrorList errors) {
        if (path == null) {
            return false;
        }
        if (path.contains("..") || path.contains("/") 
            || path.contains("\\")) {
            return false;
        }
        return true;
    }

    /**
     * Method that sanitizes a path by removing dangerous characters
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String getSanitizedFilePath(java.lang.String path) {
        if (path == null) {
            return "";
        }
        return path.replace("..", "")
                  .replace("/", "")
                  .replace("\\", "");
    }
} 