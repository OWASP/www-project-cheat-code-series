package org.owasp.cheatcode.commandinjection;

/**
 * Contains constants for legitimate command test cases used in security testing.
 */
public final class LegitimateCommandTestPayloads {
    private LegitimateCommandTestPayloads() {
        // Prevent instantiation
    }

    // Base commands for legitimate operations
    public static final String SIMPLE_ECHO = "echo Hello World";
    public static final String ECHO_WITH_QUOTES = "echo \"Hello World\"";
    public static final String ECHO_WITH_SPACES = "echo Hello World Test";
    public static final String ECHO_WITH_NUMBERS = "echo 12345";
    public static final String ECHO_EMPTY = "echo";

    // Expected outputs for verification
    public static final String EXPECTED_HELLO_WORLD = "Hello World";
    public static final String EXPECTED_QUOTES = "\"Hello World\"";
    public static final String EXPECTED_SPACES = "Hello World Test";
    public static final String EXPECTED_NUMBERS = "12345";
}