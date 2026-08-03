package org.owasp.cheatcode.commandinjection;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

/**
 * Main class demonstrating secure and insecure command execution implementations.
 * This class serves as a test harness for various command execution strategies,
 * highlighting both secure and vulnerable implementations.
 */
public class Main {
    /** ANSI color codes for console output */
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String GREEN = "\u001B[32m";
    private static final String RESET = "\u001B[0m";
    
    /** Test inputs to evaluate different command execution scenarios */
    private static final String[] TEST_INJECTION_INPUTS = {
        "",                                    // Valid command (baseline)

        // Command chaining
        " & ",                                // Basic chaining
        " && ",                               // Logical AND
        " || ",                               // Logical OR
        "; ",                                 // Command separator (Unix/Windows)

        // Pipe operations
        " | ",                                // Basic pipe
        " |& ",                               // Pipe stderr and stdout (bash)

        // Redirection attacks
        " > evil.txt",                        // Output redirection
        " >> evil.txt",                       // Append redirection
        " < C:\\Windows\\System32\\drivers\\etc\\hosts", // Input redirection (Windows)
        " 2> error.log",                      // Error redirection

        // Subcommand execution
        "; $(whoami)",                        // Command substitution (Unix)
        "; `whoami`",                         // Backtick substitution (Unix)
        " & for /f %i in ('whoami') do echo %i", // Windows for loop

        // Windows-specific
        " & dir",                             // Windows directory listing
        " && net user",                       // Windows user enumeration
        " | findstr \"admin\"",               // Windows string search
        " & echo %CD%",                       // Windows current directory
        " & echo %USERNAME%",                 // Windows username

        // Encoding/obfuscation attempts
        "%26%26",                             // URL encoded &&
        "%3B",                                // URL encoded ;
        "\n",                                 // Newline injection
        "\r\n",                               // CRLF injection

        // Multi-command attempts
        "; echo injection1 && echo injection2", // Multiple commands
        " & echo %CD% & echo %USERNAME%",     // Windows environment vars
        " && timeout 1 >nul",                // Windows timing attack

        // File system exploration
        " & dir C:\\",                        // Root directory listing
        " & type C:\\Windows\\System32\\drivers\\etc\\hosts", // File content reading

        null                                  // Null input
    };

    /** Command to test for successful injection */
    private static final String BASE_COMMAND = "echo ";

    /** Command to test for successful injection */
    private static final String LEGITIMATE_USER_INPUT = "Hello world";

    /** Command to test for successful injection */
    private static final String INJECTED_COMMAND = "ver";

    private static String ExpectedInjectionCommandExecutionResult = "";

    private static boolean isWindows = false;

    /**
     * Main entry point for the command execution demonstration.
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        if (!initializeESAPI()) {
            System.err.println("Failed to initialize ESAPI. Exiting...");
            return;
        }

        isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");

        if(!InitializeExpectedInjectionResult()) {
            System.err.println("Failed to initialize expected injection result. Exiting...");
            return;
        }
        

        CommandProcessor[] processors = createProcessors();
        runTests(processors);
    }

    private static boolean  InitializeExpectedInjectionResult()  {
        // Use cmd.exe /c to execute commands on Windows
        try {
        Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", INJECTED_COMMAND});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (!line.trim().isEmpty()) {
                output.append(line).append(System.lineSeparator());
            }
        }
        int exitCode = process.waitFor();
        //output.append("[Exit code: ").append(exitCode).append("]");
        ExpectedInjectionCommandExecutionResult = output.toString();
        return true;
        } catch (Exception e) {
            return false;
        }
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
     * Creates instances of all command processors to be tested.
     * @return Array of command processor instances
     */
    private static CommandProcessor[] createProcessors() {
        return new CommandProcessor[] {
            new VulnerableCommandProcessor_Default_NoChecks(),
            new VulnerableCommandProcessor_Java_ProcessBuilder(),
            new SecureCommandProcessor_ProcessBuilder_Whitelist()
        };
    }

    /**
     * Runs tests for all processors against all test inputs.
     * @param processors Array of command processors to test
     */
    private static void runTests(CommandProcessor[] processors) {
        for (CommandProcessor processor : processors) {
            System.out.println("\nTesting: " + processor.getClass().getSimpleName());
            System.out.println("=".repeat(50));

            for (String injectionCharacters : TEST_INJECTION_INPUTS) {
                System.out.println("\nTest input: " + injectionCharacters);
                try {
                    String command = BASE_COMMAND + LEGITIMATE_USER_INPUT;
                    if(injectionCharacters != null) {
                        command += injectionCharacters + INJECTED_COMMAND;
                    }                    
                    CommandExecutionResult result = processor.executeCommand(command);
                    handleExecutionResult(result);
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Handles the result of a command execution operation.
     * @param result The result of the command execution operation
     */
    private static void handleExecutionResult(CommandExecutionResult result) {
        if (result.hasError()) {
            System.out.println("Execution failed: " + result.executionException.toString());
        } else if (result.executionResult != null) {
            boolean injectionDetected = false;

            // Check for successful command injection indicators
            if (result.executionResult.contains(ExpectedInjectionCommandExecutionResult) ||
                result.executionResult.contains("Volume in drive") ||  // dir command output
                result.executionResult.contains("Directory of") ||     // dir command output
                result.executionResult.contains("User accounts for") || // net user output
                result.executionResult.toLowerCase().contains("administrator") || // admin user detection
                result.executionResult.contains("injection1") ||       // multi-command test
                result.executionResult.contains("injection2") ||       // multi-command test
                (result.executionResult.contains("C:\\") && !result.executionResult.contains(LEGITIMATE_USER_INPUT))) {
                injectionDetected = true;
            }

            if (injectionDetected) {
                System.out.println(RED + "INJECTION SUCCEEDED" + RESET);
            }

            if (result.executionResult.contains(LEGITIMATE_USER_INPUT)) {
                System.out.println(GREEN + "Legitimate user input succeeded" + RESET);
            } else {
                System.out.println(YELLOW + "Execution result does not contain legitimate user input" + RESET);
            }

            System.out.println("Output: " + result.executionResult);
        } else {
            System.out.println("No error and no result");
        }
    }
} 