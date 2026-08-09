package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

import org.owasp.esapi.ESAPI;

/**
 * This class contains a secure path processing implementation that uses OWASP ESAPI's
 * file name validation, driven entirely by the ESAPI configuration files rather than by
 * a list of allowed extensions hard-coded in Java.
 *
 * Both the accepted file name pattern (Validator.FileName) and the accepted extensions
 * (HttpUtilities.ApprovedUploadExtensions) come from src/main/resources/esapi/ESAPI.properties,
 * so the policy can be changed without recompiling. Compare with
 * Secure_RawString_ESAPI_FileNameHardCodedExtensions_Validator, which hard-codes its extension list.
 *
 * Note: getValidFileName rejects a null or empty extension list outright, so the configured
 * list must be passed explicitly - there is no "any extension" mode.
 */
public class Secure_RawString_ESAPI_FileNameFromConfig_Validator extends PathProcessor {

    public Secure_RawString_ESAPI_FileNameFromConfig_Validator(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Use the class name as the ESAPI validation context, so a failure names this processor
        String context = this.getClass().getSimpleName();

        if (ESAPI.validator().isValidFileName(context, userInput, false)) {
            return readFrom(Paths.get(baseDirectory, userInput));
        }

        // ESAPI is built to refuse rather than to repair. For every payload the configured
        // pattern rejects, this call throws ValidationException instead of returning a rewritten
        // name - so the caller gets an exception, not the contents of some other file. That is a
        // better failure than a silent rewrite, and it still costs subdirectory access.
        String validFileName = ESAPI.validator().getValidFileName(
            context,
            userInput,
            ESAPI.securityConfiguration().getAllowedFileExtensions(),
            false);

        return readFrom(Paths.get(baseDirectory, validFileName));
    }
}
