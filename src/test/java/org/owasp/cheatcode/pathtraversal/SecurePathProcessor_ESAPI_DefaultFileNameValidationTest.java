package org.owasp.cheatcode.pathtraversal;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.SANITIZE_FAILED;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class SecurePathProcessor_ESAPI_DefaultFileNameValidationTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_ESAPI_DefaultFileNameValidation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (ESAPI File Name Validation)";
    }

    @Override
    String describe() {
        return "The same ESAPI filename validator, but with the allowed extension list hard-coded "
             + "in Java instead of read from ESAPI.properties. Identical verdicts to the "
             + "config-driven variant; the difference is operational, not behavioural - changing "
             + "policy here means a recompile. Watch the extension argument: getValidFileName "
             + "rejects a null or empty list outright rather than treating it as 'any extension', "
             + "which silently disables the sanitiser.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, SANITIZE_FAILED,
                "A separator fails the filename pattern and getValidFileName throws rather than "
              + "repairing. Nested access is lost, with a clear exception rather than a silent "
              + "rewrite.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, SANITIZE_FAILED)
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SANITIZE_FAILED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, SANITIZE_FAILED)
            .expect(MALFORMED_NULL_BYTE, SANITIZE_FAILED,
                "Rejected by ESAPI's pattern before the JDK sees the path - a genuine defence, "
              + "unlike the seven implementations that record REJECTED_BY_RUNTIME here.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SANITIZE_FAILED,
                   "Backslash fails the filename pattern. Declared for WINDOWS only; POSIX "
                 + "behaviour not yet observed."))
            .build();
    }
}
