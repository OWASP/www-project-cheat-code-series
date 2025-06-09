package org.owasp.cheatcode.pathtraversal;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;

public class SecurePathProcessor_ESAPI_FileNameValidation extends PathProcessor {
    
    public SecurePathProcessor_ESAPI_FileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getSanitizedFilePath(java.lang.String path) throws org.owasp.esapi.errors.ValidationException {
        if (path == null) {
            return "";
        }
        // Use ESAPI's getValidFileName with class name as context
        return ESAPI.validator().getValidFileName(this.getClass().getSimpleName(), path, null, false);        
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