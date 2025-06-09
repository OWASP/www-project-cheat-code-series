package org.owasp.cheatcode.commandinjection;

/**
 * Class representing the result of a command execution operation.
 * Contains both the execution result and any exceptions that occurred.
 */
public class CommandExecutionResult {
    public String executionResult;
    public Exception executionException;
    public int exitCode;

    public CommandExecutionResult(String executionResult) {
        this.executionResult = executionResult;
        this.executionException = null;
        this.exitCode = 0;
    }
    
    public CommandExecutionResult(Exception executionException) {
        this.executionResult = null;
        this.executionException = executionException;
        this.exitCode = -1;
    }

    public boolean hasError() {
        return executionException != null;
    }
} 