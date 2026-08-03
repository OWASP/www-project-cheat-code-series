package org.owasp.cheatcode.commandinjection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Secure implementation: Uses ProcessBuilder with strict input validation and command whitelisting.
 * This implementation demonstrates proper secure command execution by:
 * 1. Validating input against dangerous characters
 * 2. Using a whitelist of allowed commands
 * 3. Proper argument parsing and validation
 * 4. Using ProcessBuilder for safer execution
 */
public class SecureCommandProcessor_ProcessBuilder_Whitelist implements CommandProcessor {

    // Whitelist of allowed commands
    private static final List<String> ALLOWED_COMMANDS = Arrays.asList(
        "echo",
        "ping",
        "nslookup"
    );

    // Pattern to detect dangerous characters that could lead to command injection
    private static final Pattern DANGEROUS_CHARS = Pattern.compile(
        "[;&|`$()<>{}\\[\\]\\\\*?~#!\\r\\n]"
    );

    // Pattern to detect path traversal attempts
    private static final Pattern PATH_TRAVERSAL = Pattern.compile(
        "\\.\\.|/|\\\\|%2e%2e|%2f|%5c"
    );

    @Override
    public CommandExecutionResult executeCommand(String commandInput) {
        if (commandInput == null) {
            return new CommandExecutionResult("Input command cannot be null");
        }

        if (commandInput.trim().isEmpty()) {
            return new CommandExecutionResult("Input command cannot be empty");
        }

        try {
            // Step 1: Validate input for dangerous characters (except quotes which we'll handle specially)
            if (containsDangerousCharactersExceptQuotes(commandInput)) {
                return new CommandExecutionResult(
                    new SecurityException("Command contains dangerous characters that could lead to injection")
                );
            }

            // Step 2: Parse command and arguments
            String[] parts = commandInput.trim().split("\\s+");
            if (parts.length == 0) {
                return new CommandExecutionResult("No command specified");
            }

            String command = parts[0].toLowerCase();

            // Step 3: Validate command against whitelist
            if (!ALLOWED_COMMANDS.contains(command)) {
                return new CommandExecutionResult(
                    new SecurityException("Command '" + command + "' is not in the allowed commands list: " + ALLOWED_COMMANDS)
                );
            }

            // Step 4: Validate arguments
            for (int i = 1; i < parts.length; i++) {
                if (!isValidArgument(parts[i])) {
                    return new CommandExecutionResult(
                        new SecurityException("Invalid argument detected: " + parts[i])
                    );
                }
            }

            // Step 5: Execute command using ProcessBuilder with validated inputs
            return executeSecureCommand(parts);

        } catch (Exception e) {
            return new CommandExecutionResult(e);
        }
    }

    /**
     * Checks if the input contains dangerous characters that could be used for injection.
     */
    private boolean containsDangerousCharacters(String input) {
        return DANGEROUS_CHARS.matcher(input).find();
    }

    /**
     * Checks if the input contains dangerous characters except quotes (which we handle specially).
     */
    private boolean containsDangerousCharactersExceptQuotes(String input) {
        return DANGEROUS_CHARS.matcher(input).find();
    }

    /**
     * Validates individual command arguments.
     */
    private boolean isValidArgument(String argument) {
        // Check for dangerous characters (excluding quotes for now)
        if (DANGEROUS_CHARS.matcher(argument).find()) {
            return false;
        }

        // Allow properly quoted strings for echo command
        if (argument.startsWith("\"") && argument.endsWith("\"") && argument.length() > 1) {
            String innerContent = argument.substring(1, argument.length() - 1);
            // Check that the inner content doesn't contain dangerous chars
            return !DANGEROUS_CHARS.matcher(innerContent).find() &&
                   !PATH_TRAVERSAL.matcher(innerContent.toLowerCase()).find();
        }

        // Check for path traversal attempts
        if (PATH_TRAVERSAL.matcher(argument.toLowerCase()).find()) {
            return false;
        }

        // Additional validation: limit argument length
        if (argument.length() > 100) {
            return false;
        }

        // For ping command, validate that arguments look like hostnames or IPs
        if (argument.contains("ping") || argument.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            // Basic IP or hostname validation
            return argument.matches("^[a-zA-Z0-9.-]+$") && argument.length() <= 253;
        }

        return true;
    }

    /**
     * Executes the validated command using ProcessBuilder.
     */
    private CommandExecutionResult executeSecureCommand(String[] commandParts) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(commandParts);

            // Security configurations
            processBuilder.redirectErrorStream(true); // Combine stdout and stderr

            // Set a controlled environment (optional - removes potentially dangerous env vars)
            processBuilder.environment().clear();
            processBuilder.environment().put("PATH", System.getenv("PATH"));

            Process process = processBuilder.start();

            // Read output with timeout protection
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            int lineCount = 0;
            final int MAX_LINES = 50; // Prevent excessive output

            while ((line = reader.readLine()) != null && lineCount < MAX_LINES) {
                if (!line.trim().isEmpty()) {
                    output.append(line).append(System.lineSeparator());
                    lineCount++;
                }
            }

            // Wait for process completion with timeout
            boolean finished = process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new CommandExecutionResult(
                    new SecurityException("Command execution timed out and was terminated")
                );
            }

            int exitCode = process.exitValue();
            var result = new CommandExecutionResult(output.toString());
            result.exitCode = exitCode;

            return result;

        } catch (Exception e) {
            return new CommandExecutionResult(e);
        }
    }
}