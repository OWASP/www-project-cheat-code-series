package org.owasp.cheatcode.commandinjection;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Secure implementation: Uses ProcessBuilder instead of Runtime.exec()
 * While this is more secure than direct Runtime.exec(), additional input validation
 * and command whitelisting would be needed for complete security.
 */
public class VulnerableCommandProcessor_Java_ProcessBuilder implements CommandProcessor {
    @Override
    public CommandExecutionResult executeCommand(String commandInput) {
        if (commandInput == null) {
            return new CommandExecutionResult("Input was null");
        }
        try {
            // Use ProcessBuilder to execute commands
            ProcessBuilder processBuilder = new ProcessBuilder("cmd.exe", "/c", commandInput);
            processBuilder.redirectErrorStream(true); // Combine stdout and stderr
            
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    output.append(line).append(System.lineSeparator());
                }
            }
            
            int exitCode = process.waitFor();
            var result = new CommandExecutionResult(output.toString());
            result.exitCode = exitCode;
            return result;
        } catch (Exception e) {
            return new CommandExecutionResult(e);
        }
    }
} 