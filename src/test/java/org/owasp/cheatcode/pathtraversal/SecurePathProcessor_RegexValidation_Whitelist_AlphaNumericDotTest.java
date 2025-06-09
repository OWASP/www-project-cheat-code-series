package org.owasp.cheatcode.pathtraversal;

class SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDotTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Whitelist)";
    }   
}