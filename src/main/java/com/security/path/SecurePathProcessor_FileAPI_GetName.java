package com.security.path;

import java.io.File;

import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a secure path processing implementation
 * that uses Java's built-in file name APIs for sanitization.
 */
public class SecurePathProcessor_FileAPI_GetName extends PathProcessor {
    
    public SecurePathProcessor_FileAPI_GetName(String baseDirectory) {
        super(baseDirectory);
    }
    

    /**
     * Method that validates a path
     * @param path The path to validate
     * @return true if the path contains only a filename, false otherwise
     */
    @Override
    public boolean isValidFilePath(String path, ValidationErrorList errors) {
        if (path == null) {
            return false;
        }
        // Validate using File.getName() to ensure it's a valid filename
        return getSanitizedFilePath(path).equals(path);
    }

    /**
     * Method that sanitizes a path by extracting only the filename component
     * using File.getName() API
     * @param path The path to sanitize
     * @return The filename component only
     */
    @Override
    public String getSanitizedFilePath(String path) {
        if (path == null) {
            return "";
        }
        // Use File.getName() to get only the filename part
        return new File(path).getName();
    }
} 