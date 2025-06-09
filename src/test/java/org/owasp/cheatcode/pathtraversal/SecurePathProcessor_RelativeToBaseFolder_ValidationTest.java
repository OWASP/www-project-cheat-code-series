package org.owasp.cheatcode.pathtraversal;

class SecurePathProcessor_RelativeToBaseFolder_ValidationTest extends BasePathProcessorTest {
    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RelativeToBaseFolder_Validation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Relative to Root Path Validation)";
    }
} 