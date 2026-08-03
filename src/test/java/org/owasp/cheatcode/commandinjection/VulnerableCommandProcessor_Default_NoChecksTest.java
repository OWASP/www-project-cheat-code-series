package org.owasp.cheatcode.commandinjection;

import org.junit.jupiter.api.DisplayName;

@DisplayName("Vulnerable Command Processor - Default No Checks Tests")
class VulnerableCommandProcessor_Default_NoChecksTest extends BaseCommandProcessorTest {

    @Override
    CommandProcessor createProcessor() {
        return new VulnerableCommandProcessor_Default_NoChecks();
    }

    @Override
    String getProcessorName() {
        return "VulnerableCommandProcessor_Default_NoChecks";
    }
}