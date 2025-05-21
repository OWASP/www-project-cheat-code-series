package com.security.path;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.owasp.esapi.ValidationErrorList;

/**
 * Abstract base class for path processing implementations.
 * Defines the contract for path processing operations and provides common functionality
 * for handling file paths securely. This class implements the core logic for detecting
 * and handling path traversal attacks.
 */
public abstract class PathProcessor {

    protected final String baseDirectory;

    /**
     * Flag indicating whether path validation is enabled for this processor.
     * When true, paths will be validated before processing.
     */
    //public static boolean CanValidate = true;

    /**
     * Flag indicating whether path sanitization is supported by this processor.
     * When true, invalid paths will be sanitized instead of rejected.
     */
    protected boolean CanSanitize = true;

    /**
     * Constructs a new PathProcessor with the specified base directory.
     * 
     * @param baseDirectory The root directory that all paths will be relative to
     */
    protected PathProcessor(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    /**
     * Calculates the target path by validating and optionally sanitizing the user input.
     * This method implements the core path traversal detection and handling logic.
     * 
     * @param userInput The user-provided path to process
     * @return ReadFileResult containing the processed path and any validation/sanitization results
     */
    public ReadFileResult CalculateTargetPath(String userInput) {
        
        ReadFileResult result = new ReadFileResult();
        if (userInput == null || userInput.isEmpty()) {
            result.fileReadException = new org.owasp.esapi.errors.ValidationException("Input directory path required", "Input directory path required");
            return result;
        }
        
        result.userProvidedPath = userInput;
        try {

            if (isValidFilePath(userInput, null)) {
                // No Path traversal attack detected
                result.IsPathTraversalAttackDetected = false;
                result.IsPathSanitized = false;
                result.executedSanitizedFilePath = this.JoinPaths(this.baseDirectory, userInput);
            } else {
                // Path traversal attack detected
                result.IsPathTraversalAttackDetected = true;
                if (CanSanitize) {
                    // Sanitize the input
                    String sanitizedInput = getSanitizedFilePath(userInput);
                    result.IsPathSanitized = true;
                    result.executedSanitizedFilePath = this.JoinPaths(this.baseDirectory, sanitizedInput);
                } else {
                    // Sanitization is not supported
                    result.IsPathSanitized = false;
                    result.fileReadException = new UnsupportedOperationException(
                            "PathTraversal is detected. Sanitization is not supported for this processor");
                }
            }
        }
        catch (Exception e) {
            result.fileReadException = e;
        }
        return result;
    }

    /**
     * Safely joins two paths using the system's path separator.
     * This method ensures proper path concatenation.
     * 
     * @param basePath The base directory path
     * @param userInput The user-provided path to append
     * @return A Path object representing the joined paths
     */
    protected Path JoinPaths(String basePath, String userInput) {
        return Paths.get(basePath, userInput);
    }

    /**
     * Reads the content of a file after validating and processing its path.
     * This method handles the complete file reading process including path validation,
     * sanitization, and error handling.
     * 
     * @param userProvidedFileName The file name provided by the user
     * @return ReadFileResult containing the file content and any processing results
     */
    public ReadFileResult readFile(String userProvidedFileName) {
        ReadFileResult result = CalculateTargetPath(userProvidedFileName);

        if (result.fileReadException != null) {
            return result;
        }

        try {
            result.fileReadResult = Files.readString(result.executedSanitizedFilePath);
        } catch (Exception e) {
            result.fileReadException = e;
        }

        return result;
    }

    /**
     * Validates if the provided path is safe to use.
     * This method should be implemented by concrete classes to provide specific
     * validation logic based on their security requirements.
     * 
     * @param userInput The path to validate
     * @param errors List to collect any validation errors encountered during path validation
     * @return true if the path is valid and safe to use, false otherwise
     */
    public abstract boolean isValidFilePath(String userInput, ValidationErrorList errors);

    /**
     * Sanitizes the provided path to make it safe for use.
     * This method should be implemented by concrete classes to provide specific
     * sanitization logic based on their security requirements.
     * 
     * @param userProvidedFileName The path to sanitize
     * @return A sanitized version of the path that is safe to use
     */
    public abstract String getSanitizedFilePath(String userProvidedFileName) throws org.owasp.esapi.errors.ValidationException;
}