package org.owasp.cheatcode.pathtraversal;

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
            new Vulnerable_None_JavaNIO_PathsGet_NoDefence(BASE_DIR),
            new Vulnerable_None_JavaNIO_StringConcat_NoDefence(BASE_DIR),            
            // Adjacent on purpose: identical `../` rule, refused by one and repaired by the other.
            new Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator(BASE_DIR),
            new Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer(BASE_DIR),
            new Vulnerable_None_Spring_GetOriginalFilename_FalseSanitizer(BASE_DIR),
            new Secure_RawString_StringOps_StripSeparators_Sanitizer(BASE_DIR),
            new Secure_RawString_Regex_DenySeparators_Sanitizer(BASE_DIR),
            new Secure_RawString_Regex_DenyWindowsUnsafeChars_Sanitizer(BASE_DIR),
            new Secure_RawString_Regex_AllowAlphaNumericDot_Validator(BASE_DIR),
            new Secure_ResolvedPath_JavaFileAPI_CanonicalVsAbsolute_Validator(BASE_DIR),
            new Secure_ResolvedPath_JavaFileAPI_CanonicalStartsWithBase_Validator(BASE_DIR),
            new Secure_RawString_JavaFileAPI_GetName_Sanitizer(BASE_DIR),
            new Secure_RawString_ESAPI_FileNameFromConfig_Validator(BASE_DIR),
            new Secure_RawString_ESAPI_FileNameHardCodedExtensions_Validator(BASE_DIR),
            new Secure_RawString_ESAPI_DirectoryAndFileName_Validator(BASE_DIR)
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