package org.owasp.cheatcode.pathtraversal;

class SecurePathProcessor_ESAPI_DefaultFileNameValidationTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_ESAPI_DefaultFileNameValidation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (ESAPI File Name Validation)";
    }
} 