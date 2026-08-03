package org.owasp.cheatcode.commandinjection;

import org.junit.jupiter.api.DisplayName;

@DisplayName("Secure Command Processor - ProcessBuilder Whitelist Tests")
class SecureCommandProcessor_ProcessBuilder_WhitelistTest extends BaseCommandProcessorTest {

    @Override
    CommandProcessor createProcessor() {
        return new SecureCommandProcessor_ProcessBuilder_Whitelist();
    }

    @Override
    String getProcessorName() {
        return "SecureCommandProcessor_ProcessBuilder_Whitelist";
    }
}