package org.owasp.cheatcode.pathtraversal;

import java.util.regex.Pattern;

import org.owasp.esapi.ValidationErrorList;

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
    
    /**
     * Method that validates a path using regex pattern
     * @param path The path to validate
     * @return true if the path is valid, false otherwise
     */
    @Override
    public boolean isValidFilePath(java.lang.String path, ValidationErrorList errors) {
        if (path == null) {
            return false;
        }
        return !Pattern.compile(DANGEROUS_CHARS_PATTERN).matcher(path).find() && !path.contains("\0");
    }

    /**
     * Method that sanitizes a path by replacing unsafe characters
     * @param path The path to sanitize
     * @return The sanitized path
     */
    @Override
    public String getSanitizedFilePath(java.lang.String path) {
        if (path == null) {
            return "";
        }
        //Replace invalid characters with underscore and remove null characters (\0) entirely
        return path.replaceAll(DANGEROUS_CHARS_PATTERN, "_").replaceAll("\0", "");
    }
} 