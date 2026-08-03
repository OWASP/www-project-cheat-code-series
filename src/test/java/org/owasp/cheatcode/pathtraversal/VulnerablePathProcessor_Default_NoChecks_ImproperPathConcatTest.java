package org.owasp.cheatcode.pathtraversal;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.REJECTED_BY_RUNTIME;
import static org.owasp.cheatcode.harness.Outcome.SECRET_DISCLOSED;
import static org.owasp.cheatcode.harness.Outcome.UNDETECTED_MISS;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class VulnerablePathProcessor_Default_NoChecks_ImproperPathConcatTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (No Checks and Improper Path String Concat)";
    }

    @Override
    String describe() {
        return "Builds the target path by string concatenation (base + separator + input) rather "
             + "than Paths.get(base, input). It scores identically to plain No Checks, which is "
             + "the point worth noticing: swapping concatenation for the path API fixes nothing on "
             + "its own. What is missing is validation, not a safer join.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK)
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, UNDETECTED_MISS,
                "Not detected. Lands one directory short of the secret because of the fixture "
              + "layout, not because of anything the implementation does.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SECRET_DISCLOSED,
                "Concatenation produces the same escaping path the path API would have, and the "
              + "secret is disclosed. Identical to No Checks - the join was never the flaw.")
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, UNDETECTED_MISS,
                "Resolves to a directory literally named `....`, which does not exist. This "
              + "payload only defeats implementations that strip `../`.")
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "InvalidPathException from the JDK, not a defence in this code.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SECRET_DISCLOSED,
                   "Backslash is a separator on Windows. Declared for WINDOWS only - the POSIX "
                 + "behaviour has not been observed yet."))
            .build();
    }
}
