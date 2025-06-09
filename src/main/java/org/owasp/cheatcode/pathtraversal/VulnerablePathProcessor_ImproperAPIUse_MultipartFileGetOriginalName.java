package org.owasp.cheatcode.pathtraversal;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

/**
 * This class contains a vulnerable path processing implementation
 * that uses MultipartFile.getOriginalFilename() for path processing.
 * This is vulnerable because getOriginalFilename() returns the original filename
 * from the client without any sanitization, making it susceptible to path traversal attacks.
 */
public class VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName extends PathProcessor {
    
    public VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName(String baseDirectory) {
        super(baseDirectory);
    }

    /**
     * Vulnerable method that validates a path using MultipartFile.getOriginalFilename()
     * @param path The path to validate
     * @return true if the path is not null, false otherwise
     */
    @Override
    public boolean isValidFilePath(String path, ValidationErrorList errors) {
        if (path == null) {
            return false;
        }
        try {
            var sanitizedFileName = getSanitizedFilePath(path);
            return sanitizedFileName.equals(path);
        } catch (ValidationException vex) {
            errors.addError("Validation with MultipartFile: ", vex);
            return false;
        }
    }

    /**
     * Vulnerable method that uses the original filename.
     * MultipartFile.getOriginalFilename() returns the original filename and may contain path information depending on the browser used
     * https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/multipart/MultipartFile.html#getOriginalFilename()
     * @param path The path to sanitize
     * @return The original filename without any sanitization
     */
    @Override
    public String getSanitizedFilePath(String path) throws ValidationException {
        if (path == null || path.isEmpty()) {
            throw new ValidationException("Input directory path required", "Input directory path required");
        }
        try {
            // Create a real MultipartFile using MockMultipartFile            
            MultipartFile multipartFile = this.createMockMultipartFile(path);
            return multipartFile.getOriginalFilename();
        } catch (Exception e) {
            throw new ValidationException("Failed to sanitize path using MultipartFile.getOriginalFilename()",e.getMessage(), e);
        }
    }

    /**
     * Creates a mock MultipartFile in memory without writing to disk.
     * Uses MockMultipartFile which preserves the original filename exactly as provided.
     * @param path The path to use for the mock file
     * @return A MultipartFile instance with the specified path
     */
    private MultipartFile createMockMultipartFile(String path) {
        return new MockMultipartFile("file", path, "text/plain", "fake content".getBytes());
    }
} 