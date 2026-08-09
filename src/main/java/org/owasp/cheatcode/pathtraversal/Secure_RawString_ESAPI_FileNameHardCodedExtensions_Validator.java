package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import org.owasp.esapi.ESAPI;

/**
 * This class contains a secure path processing implementation
 * that uses OWASP ESAPI's file name validation.
 */
public class Secure_RawString_ESAPI_FileNameHardCodedExtensions_Validator extends PathProcessor {

    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(
        "txt", "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif"
    );

    public Secure_RawString_ESAPI_FileNameHardCodedExtensions_Validator(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Worth noticing, and preserved exactly as it was: the check below reads its extension
        // list from ESAPI.properties, while the call after it uses the hard-coded
        // ALLOWED_EXTENSIONS above. Two sources of truth for one policy. Splitting this across
        // a validate method and a sanitize method is what kept it invisible.
        if (ESAPI.validator().isValidFileName("ESAPI FileName Validation", userInput, false)) {
            return readFrom(Paths.get(baseDirectory, userInput));
        }

        String validFileName;
        try {
            // ESAPI throws on an attack payload rather than sanitizing it, so in practice this
            // is a rejection carrying an exception rather than a second attempt.
            validFileName = ESAPI.validator().getValidFileName(
                "ESAPI FileName Validation", userInput, ALLOWED_EXTENSIONS, false);
        } catch (Exception e) {
            throw new org.owasp.esapi.errors.ValidationException(
                "Failed to sanitize path using ESAPI.getValidFileName()", e.getMessage(), e);
        }

        // Deliberately outside the catch above: a failed read must stay a failed read, and not
        // be reported as a validation failure.
        return readFrom(Paths.get(baseDirectory, validFileName));
    }
}
