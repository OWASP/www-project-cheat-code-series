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

class SecurePathProcessor_RelativeToBaseFolder_ValidationTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RelativeToBaseFolder_Validation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Relative to Root Path Validation)";
    }

    @Override
    String describe() {
        return "Resolves the input against the base directory, canonicalises both, and requires "
             + "the result to sit underneath the base directory. The recommended technique: it "
             + "asks the question that actually matters - does the resolved path stay inside the "
             + "boundary? - rather than trying to enumerate the ways input can be dangerous.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK,
                "Nested access is fine because it resolves inside the boundary. Containment is "
              + "the only approach here that gets both halves right without an exception list.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED,
                "Resolves outside the base directory and is refused. Notably this is the only "
              + "family that treats the single-level payload as an attack rather than letting the "
              + "fixture layout make it a near miss - containment does not care whether the "
              + "escaped path happens to hold anything interesting.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED,
                "Padded dots survive naive stripping but not canonicalisation, which is the point: "
              + "resolve first, then compare, and payload encoding stops mattering.")
            .expect(MALFORMED_NULL_BYTE, REJECTED,
                "getCanonicalPath throws on the invalid character and the validator answers false. "
              + "Detected by the implementation rather than left to the JDK.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, REJECTED,
                   "Resolves outside the base directory on Windows. Declared for WINDOWS only; "
                 + "POSIX behaviour not yet observed."))
            .build();
    }
}
