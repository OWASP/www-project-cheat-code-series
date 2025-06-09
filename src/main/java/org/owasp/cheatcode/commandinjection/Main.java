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
        "",                              // Valid command
        " & ",          // Command chaining attempt
                         // Command separator injection
        " && ",              // Logical AND injection
        " || ",                 // Logical OR injection
        " | ",       // Pipe injection
        //" > malicious.txt && echo INJECTION_SUCCESSFUL",   // Output redirection injection
        null                                // Null input
    };

    /** Command to test for successful injection */
    private static final String BASE_COMMAND = "echo ";

    /** Command to test for successful injection */
    private static final String LEGITIMATE_USER_INPUT = "Hello world";

    /** Command to test for successful injection */
    private static final String INJECTED_COMMAND = "ver";

    private static String ExpectedInjectionCommandExecutionResult = "";

    /**
     * Main entry point for the command execution demonstration.
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        if (!initializeESAPI()) {
            System.err.println("Failed to initialize ESAPI. Exiting...");
            return;
        }

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
            new VulnerableCommandProcessor_Java_ProcessBuilder()
            // Secure and other vulnerable implementations can be added here
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
        } else if (result.executionResult != null)
        {
            if (result.executionResult.contains(ExpectedInjectionCommandExecutionResult)) {
                System.out.println(RED + "INJECTION SUCCEEDED" + RESET);
            }

            if(result.executionResult.contains(LEGITIMATE_USER_INPUT)) {
                System.out.println(GREEN + "Legitimate user input succeeded: " + RESET);
            }
            else {
                System.out.println(YELLOW + "Execution result does not contain legitimate user input" + RESET);
            }

            System.out.println(result.executionResult);
        } else {
            System.out.println("No error and no result");
        }
    }
} 