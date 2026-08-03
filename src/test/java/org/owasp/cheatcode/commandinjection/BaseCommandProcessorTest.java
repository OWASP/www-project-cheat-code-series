package org.owasp.cheatcode.commandinjection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Command Processor Tests")
abstract class BaseCommandProcessorTest {

    protected CommandProcessor processor;
    private static final String RED = "\u001B[31m";
    private static final String RESET = "\u001B[0m";

    // Expected injection result indicators
    private static final String WINDOWS_VERSION_INDICATOR = "Microsoft Windows";
    private static final String INJECTION_SUCCESS_MARKER = "injection1";
    private static final String INJECTION_SUCCESS_MARKER_2 = "injection2";

    abstract CommandProcessor createProcessor();
    abstract String getProcessorName();

    @BeforeEach
    void setUp() {
        processor = createProcessor();
        System.out.println("\nTesting " + processor.getClass().getSimpleName() + ":");
    }

    @Test
    @DisplayName("Legitimate command execution should succeed")
    void LegitCase_SimpleEcho_ShouldExecuteSuccessfully() {
        CommandExecutionResult result = processor.executeCommand(LegitimateCommandTestPayloads.SIMPLE_ECHO);

        assertFalse(result.hasError(), "Legitimate command should not fail");
        assertNotNull(result.executionResult, "Should have execution result");
        assertTrue(result.executionResult.contains(LegitimateCommandTestPayloads.EXPECTED_HELLO_WORLD),
                  "Should contain expected output: " + LegitimateCommandTestPayloads.EXPECTED_HELLO_WORLD);
    }

    @Test
    @DisplayName("Echo with quotes should execute properly")
    void LegitCase_EchoWithQuotes_ShouldHandleQuotesCorrectly() {
        CommandExecutionResult result = processor.executeCommand(LegitimateCommandTestPayloads.ECHO_WITH_QUOTES);

        assertFalse(result.hasError(), "Legitimate command with quotes should not fail");
        assertNotNull(result.executionResult, "Should have execution result");
    }

    @Test
    @DisplayName("Basic command chaining injection should be prevented")
    void AttackCase_BasicChaining_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.BASIC_CHAINING + "ver";
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Basic command chaining (&)");
    }

    @Test
    @DisplayName("Logical AND injection should be prevented")
    void AttackCase_LogicalAnd_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.LOGICAL_AND + "ver";
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Logical AND (&&)");
    }

    @Test
    @DisplayName("Logical OR injection should be prevented")
    void AttackCase_LogicalOr_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.LOGICAL_OR + "ver";
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Logical OR (||)");
    }

    @Test
    @DisplayName("Command separator injection should be prevented")
    void AttackCase_CommandSeparator_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.COMMAND_SEPARATOR + "ver";
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Command separator (;)");
    }

    @Test
    @DisplayName("Pipe injection should be prevented")
    void AttackCase_BasicPipe_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.BASIC_PIPE + "findstr hello";
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Basic pipe (|)");
    }

    @Test
    @DisplayName("Windows directory listing injection should be prevented")
    void AttackCase_WindowsDir_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.WINDOWS_DIR;
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Windows directory listing");
    }

    @Test
    @DisplayName("Windows net user injection should be prevented")
    void AttackCase_WindowsNetUser_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.WINDOWS_NET_USER;
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Windows net user enumeration");
    }

    @Test
    @DisplayName("Multi-command injection should be prevented")
    void AttackCase_MultiCommand_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.MULTI_ECHO;
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Multi-command injection");
    }

    @Test
    @DisplayName("File redirection injection should be prevented")
    void AttackCase_OutputRedirection_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.OUTPUT_REDIRECT;
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Output redirection");
    }

    @Test
    @DisplayName("Environment variable injection should be prevented")
    void AttackCase_EnvironmentVariables_ShouldPreventInjection() {
        String maliciousCommand = "echo hello" + CommandInjectionTestPayloads.WINDOWS_USERNAME;
        CommandExecutionResult result = processor.executeCommand(maliciousCommand);

        assertInjectionPrevented(result, "Environment variable injection");
    }

    @Test
    @DisplayName("Null input should be handled gracefully")
    void EdgeCase_NullInput_ShouldHandleGracefully() {
        CommandExecutionResult result = processor.executeCommand(null);

        // Should either fail gracefully or return an error result
        assertTrue(result.hasError() || result.executionResult != null,
                  "Null input should be handled gracefully");
    }

    @Test
    @DisplayName("Empty input should be handled gracefully")
    void EdgeCase_EmptyInput_ShouldHandleGracefully() {
        CommandExecutionResult result = processor.executeCommand("");

        // Should either fail gracefully or return an error result
        assertTrue(result.hasError() || result.executionResult != null,
                  "Empty input should be handled gracefully");
    }

    /**
     * Helper method to assert that command injection was prevented.
     * This method checks that the injected command was not executed.
     */
    private void assertInjectionPrevented(CommandExecutionResult result, String attackType) {
        if (!result.hasError() && result.executionResult != null) {
            // Check for common injection success indicators
            boolean injectionSucceeded =
                result.executionResult.contains(WINDOWS_VERSION_INDICATOR) ||
                result.executionResult.contains("Volume in drive") ||
                result.executionResult.contains("Directory of") ||
                result.executionResult.contains("User accounts for") ||
                result.executionResult.toLowerCase().contains("administrator") ||
                result.executionResult.contains(INJECTION_SUCCESS_MARKER) ||
                result.executionResult.contains(INJECTION_SUCCESS_MARKER_2) ||
                result.executionResult.contains("C:\\") ||
                result.executionResult.contains("evil.txt created") ||
                (result.executionResult.split("\\r?\\n").length > 2); // Multiple lines might indicate command chaining

            assertFalse(injectionSucceeded,
                       RED + "INJECTION SUCCEEDED for " + attackType + "! Output: " + result.executionResult + RESET);
        }

        // If execution failed, that's acceptable for security (command was blocked)
        // If execution succeeded but without injection indicators, that's also acceptable
    }
}