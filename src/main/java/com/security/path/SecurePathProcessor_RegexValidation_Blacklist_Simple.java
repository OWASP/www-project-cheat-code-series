package com.security.path;

import java.util.regex.Pattern;

import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a secure path processing implementation
 * that uses simple string validation.
 */
public class SecurePathProcessor_RegexValidation_Blacklist_Simple extends PathProcessor {
    
    // Regex pattern for dangerous characters: .. or / or \
    private static final String DANGEROUS_CHARS_REGEX_PATTERN = "\\.\\.|[/\\\\]";
    
    public SecurePathProcessor_RegexValidation_Blacklist_Simple(String baseDirectory) {
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
        return !Pattern.compile(DANGEROUS_CHARS_REGEX_PATTERN).matcher(path).find();
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
        return path.replaceAll(DANGEROUS_CHARS_REGEX_PATTERN, "");
    }
} 