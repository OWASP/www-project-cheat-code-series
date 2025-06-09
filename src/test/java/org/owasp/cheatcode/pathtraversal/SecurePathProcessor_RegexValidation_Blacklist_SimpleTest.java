package org.owasp.cheatcode.pathtraversal;  

class SecurePathProcessor_RegexValidation_Blacklist_SimpleTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Blacklist_Simple(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Simple)";
    }
} 