package org.owasp.cheatcode.pathtraversal;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.REJECTED;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class SecurePathProcessor_RelativePath_ValidationTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RelativePath_Validation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Relative Path Validation)";
    }

    @Override
    String describe() {
        return "Canonicalises the input and requires that it normalise to itself, i.e. that it "
             + "contains no traversal at all, and rejects absolute paths. One of only two "
             + "implementations that blocks every payload and still serves subdirectories. Note "
             + "that it canonicalises relative to the working directory rather than to the base "
             + "directory - it is really asking 'does this path contain traversal?', which is "
             + "sufficient here but is a weaker question than containment.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK,
                "Nested access survives, because the check asks whether the path traverses rather "
              + "than reducing it to a bare filename. This cell is the whole argument for "
              + "canonicalisation over filtering.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED,
                "Canonicalising removes the `..`, so the path no longer equals itself and is "
              + "refused outright - it throws rather than repairing, so there is no repair to "
              + "get wrong.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED)
            .expect(MALFORMED_NULL_BYTE, REJECTED,
                "Detected by the implementation, not the JDK: getCanonicalPath throws IOException "
              + "on the invalid character, the validator answers false, and the input is refused. "
              + "One of only four implementations that reject this payload on their own terms.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, REJECTED,
                   "Canonicalisation resolves the backslash traversal on Windows. Declared for "
                 + "WINDOWS only; POSIX behaviour not yet observed."))
            .build();
    }
}
