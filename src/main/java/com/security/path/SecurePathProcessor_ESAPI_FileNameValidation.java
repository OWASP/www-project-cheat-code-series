package com.security.path;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;

public class SecurePathProcessor_ESAPI_FileNameValidation extends PathProcessor {
    
    public SecurePathProcessor_ESAPI_FileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getSanitizedFilePath(java.lang.String path) {
        if (path == null) {
            return "";
        }
        
        try {
            // Use ESAPI's getValidFileName with class name as context
            return ESAPI.validator().getValidFileName(this.getClass().getSimpleName(), path, null, false);
            // If validation fails, return empty string
            return "";
        }
    }

    @Override
    public boolean isValidFilePath(java.lang.String path, ValidationErrorList errors) {
        if (path == null) {
            return false;
        }
        // Use ESAPI's isValidFileName with class name as context
        return ESAPI.validator().isValidFileName(this.getClass().getSimpleName(), path, false);
    }
} 