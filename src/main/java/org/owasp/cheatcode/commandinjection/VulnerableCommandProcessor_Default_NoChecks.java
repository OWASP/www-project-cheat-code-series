package org.owasp.cheatcode.commandinjection;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Vulnerable implementation: Executes command input directly with no validation or checks.
 * Demonstrates a classic command injection vulnerability.
 */
public class VulnerableCommandProcessor_Default_NoChecks implements CommandProcessor {
    @Override
    public CommandExecutionResult executeCommand(String commandInput) {
        if (commandInput == null) {
            return new CommandExecutionResult("Input was null");
        }
        try {
            // Use cmd.exe /c to execute commands on Windows
            Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", commandInput});
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