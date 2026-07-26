package org.owasp.cheatcode.pathtraversal;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;

/**
 * This class contains a secure path processing implementation that uses OWASP ESAPI's
 * file name validation, driven entirely by the ESAPI configuration files rather than by
 * a list of allowed extensions hard-coded in Java.
 *
 * Both the accepted file name pattern (Validator.FileName) and the accepted extensions
 * (HttpUtilities.ApprovedUploadExtensions) come from src/main/resources/esapi/ESAPI.properties,
 * so the policy can be changed without recompiling. Compare with
 * SecurePathProcessor_ESAPI_DefaultFileNameValidation, which hard-codes its extension list.
 *
 * Note: getValidFileName rejects a null or empty extension list outright, so the configured
 * list must be passed explicitly - there is no "any extension" mode.
 */
public class SecurePathProcessor_ESAPI_FileNameValidation extends PathProcessor {

    public SecurePathProcessor_ESAPI_FileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getSanitizedFilePath(java.lang.String path) throws org.owasp.esapi.errors.ValidationException {
        if (path == null) {
            return "";
        }
        // Use ESAPI's getValidFileName with class name as context, taking the allowed
        // extensions from ESAPI.properties (HttpUtilities.ApprovedUploadExtensions)
        return ESAPI.validator().getValidFileName(
            this.getClass().getSimpleName(),
            path,
            ESAPI.securityConfiguration().getAllowedFileExtensions(),
            false);
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