package com.security.path;

import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

/**
 * Main class demonstrating secure and insecure path processing implementations.
 * This class serves as a test harness for various path processing strategies,
 * highlighting both secure and vulnerable implementations.
 */
public class Main {
    /** Base directory for secure storage operations */
    private static final String BASE_DIR = "secureStorage/baseDir";
    
    /** ANSI color codes for console output */
    private static final String RED = "\u001B[31m";
    private static final String RESET = "\u001B[0m";
    
    /** Test paths to evaluate different path processing scenarios */
    private static final String[] TEST_PATHS = {
        "legit.txt",                         // Valid file in secure storage
        "SomeSubFolder/sublegit.txt",        // Valid file in subfolder of secure storage
        "../pwnStorage/secret.txt",          // Basic traversal attempt, 1 level up
        "../../pwnStorage/secret.txt",       // Basic traversal attempt, 2 levels up   
        "....//....//pwnStorage//secret.txt",// Double dot traversal
        "..\\..\\pwnStorage\\secret.txt",    // Windows-style traversal
        null                                 // Null input
    };

    /**
     * Main entry point for the path processing demonstration.
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        if (!initializeESAPI()) {
            System.err.println("Failed to initialize ESAPI. Exiting...");
            return;
        }

        PathProcessor[] processors = createProcessors();
        runTests(processors);
    }

    /**
     * Initializes the ESAPI security configuration.
     * @return true if initialization was successful, false otherwise
     */
    private static boolean initializeESAPI() {
        try {
            String resourcePath = Main.class.getClassLoader().getResource("esapi").getPath();
            SecurityConfiguration config = DefaultSecurityConfiguration.getInstance();
            config.setResourceDirectory(resourcePath);
            return true;
        } catch (Exception e) {
            System.err.println("Failed to set ESAPI resource directory: " + e.getMessage());
            return false;
        }
    }

    /**
     * Creates instances of all path processors to be tested.
     * @return Array of path processor instances
     */
    private static PathProcessor[] createProcessors() {
        return new PathProcessor[] {
            new VulnerablePathProcessor_Default_NoChecks(BASE_DIR),
            new VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat(BASE_DIR),            
            new VulnerablePathProcessor_Bypassable_StringContainsCheck(BASE_DIR),
            new VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName(BASE_DIR),
            new SecurePathProcessor_StringContains_Simple(BASE_DIR),
            new SecurePathProcessor_RegexValidation_Blacklist_Simple(BASE_DIR),
            new SecurePathProcessor_RegexValidation_Blacklist_Extended(BASE_DIR),
            new SecurePathProcessor_RelativePath_Validation(BASE_DIR),
            new SecurePathProcessor_FileAPI_GetName(BASE_DIR),
            new SecurePathProcessor_ESAPI_DefaultFileNameValidation(BASE_DIR),
            new Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation(BASE_DIR)
        };
    }

    /**
     * Runs tests for all processors against all test paths.
     * @param processors Array of path processors to test
     */
    private static void runTests(PathProcessor[] processors) {
        for (PathProcessor processor : processors) {
            System.out.println("\nTesting: " + processor.getClass().getSimpleName());
            System.out.println("=".repeat(50));

            for (String testPath : TEST_PATHS) {
                System.out.println("\nTest path: " + testPath);
                try {                    
                    ReadFileResult result = processor.readFile(testPath);
                    handleReadResult(result);                    
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Handles the result of a file read operation.
     * @param result The result of the file read operation
     */
    private static void handleReadResult(ReadFileResult result) {
        if (result.fileReadException != null) {
            System.out.println("Read operation: Failed - " + result.fileReadException.toString());
        } else if (result.fileReadResult != null && result.fileReadResult.contains("CONFIDENTIAL")) {
            System.out.println(RED + "INJECTION SUCCEEDED: " + result.fileReadResult + RESET);
        } else {
            System.out.println("Read operation succeeded: " + result.fileReadResult);
        }
    }
} 