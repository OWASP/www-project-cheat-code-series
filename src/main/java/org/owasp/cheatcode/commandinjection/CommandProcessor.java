package org.owasp.cheatcode.commandinjection;

/**
 * Interface defining the contract for command processing implementations.
 * This interface is used to demonstrate both secure and vulnerable command execution patterns.
 */
public interface CommandProcessor {
    /**
     * Processes and executes the provided command input.
     * @param commandInput The command input to process and execute
     * @return CommandExecutionResult containing the execution result or error
     */
    CommandExecutionResult executeCommand(String commandInput);
} 