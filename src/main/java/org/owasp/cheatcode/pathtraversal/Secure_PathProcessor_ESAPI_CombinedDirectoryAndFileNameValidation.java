package org.owasp.cheatcode.pathtraversal;

import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ValidationException;

/**
 * This class contains a secure path processing implementation
 * that uses OWASP ESAPI's directory path validation.
 */
public class Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation extends PathProcessor {

    // List of allowed file extensions
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("txt", "pdf", "doc", "docx", "xls", "xlsx");

    public Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Split the path into directory and filename components, once
        File file = new File(userInput);
        String directoryPath = file.getParent();
        String fileName = file.getName();

        boolean isFileNameValid = ESAPI.validator().isValidFileName(
            "ESAPI FileName Validation",
            fileName,
            ALLOWED_EXTENSIONS,
            false
        );

        // Only validate the directory path if there is one
        boolean isDirectoryValid = directoryPath == null
            || ESAPI.validator().isValidDirectoryPath(
                "ESAPI DirectoryPath Validation",
                directoryPath,
                new File(this.baseDirectory),
                false
            );

        if (isFileNameValid && isDirectoryValid) {
            return readFrom(Paths.get(baseDirectory, userInput));
        }

        // In principle this is the ESAPI shape that should keep subdirectories working, because
        // it validates a directory component instead of forbidding one. In practice both
        // getValid* calls throw rather than repair, so it scores exactly like the filename-only
        // implementations - including on `SomeSubFolder/sublegit.txt`, the one input it was
        // supposed to handle better. That negative result is why this class is worth keeping.
        String validatedFileName;
        String validatedDirectory;
        try {
            validatedFileName = ESAPI.validator().getValidFileName(
                "ESAPI FileName Validation",
                fileName,
                ALLOWED_EXTENSIONS,
                false
            );

            validatedDirectory = directoryPath == null ? "."
                : ESAPI.validator().getValidDirectoryPath(
                    "ESAPI DirectoryPath Validation",
                    directoryPath,
                    new File(this.baseDirectory),
                    false
                );
        } catch (ValidationException e) {
            throw new RuntimeException("Validation failed: " + e.getMessage(), e);
        }

        // Outside the catch: a failed read must not be reported as a validation failure.
        return readFrom(Paths.get(baseDirectory,
                new File(validatedDirectory, validatedFileName).getPath()));
    }
}
