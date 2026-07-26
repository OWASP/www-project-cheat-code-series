package org.owasp.cheatcode.pathtraversal;

class SecurePathProcessor_ESAPI_FileNameValidationTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_ESAPI_FileNameValidation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (ESAPI File Name Validation, extensions from ESAPI.properties)";
    }
}
