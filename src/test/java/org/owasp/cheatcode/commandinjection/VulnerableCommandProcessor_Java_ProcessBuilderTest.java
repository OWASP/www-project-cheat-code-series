package org.owasp.cheatcode.commandinjection;

import org.junit.jupiter.api.DisplayName;

@DisplayName("Vulnerable Command Processor - Java ProcessBuilder Tests")
class VulnerableCommandProcessor_Java_ProcessBuilderTest extends BaseCommandProcessorTest {

    @Override
    CommandProcessor createProcessor() {
        return new VulnerableCommandProcessor_Java_ProcessBuilder();
    }

    @Override
    String getProcessorName() {
        return "VulnerableCommandProcessor_Java_ProcessBuilder";
    }
}