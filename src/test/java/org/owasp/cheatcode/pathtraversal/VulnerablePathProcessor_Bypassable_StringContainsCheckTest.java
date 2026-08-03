package org.owasp.cheatcode.pathtraversal;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.REJECTED_BY_RUNTIME;
import static org.owasp.cheatcode.harness.Outcome.SANITIZED_MISS;
import static org.owasp.cheatcode.harness.Outcome.SECRET_DISCLOSED;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class VulnerablePathProcessor_Bypassable_StringContainsCheckTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_Bypassable_StringContainsCheck(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (Bypassable 'String Contains' Check)";
    }

    @Override
    String describe() {
        return "Rejects any input containing the literal `../`, and repairs by deleting it. The "
             + "most instructive row in the matrix: a defence that genuinely works against the "
             + "obvious payloads and fails against the ones written to beat it. A per-class "
             + "'is this vulnerable?' flag could not describe this row at all.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK,
                "Keeps subdirectory access, because it filters a substring rather than reducing "
              + "input to a bare filename. Exactly the functionality the secure filename-only "
              + "processors give up - and it is not safe.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, SANITIZED_MISS,
                "Caught: contains `../`. Deleting it leaves `pwnStorage/secret.txt`, which does "
              + "not exist under the base directory. Blocked - by repair rather than refusal.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SANITIZED_MISS,
                "Also caught. Deleting every `../` leaves `pwnStorage/secret.txt` under the base "
              + "directory, which does not exist.")
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, SECRET_DISCLOSED,
                "The bypass, and not by evading the check: `....//` does contain a literal `../`, "
              + "so the check fires and the repair runs. Deleting the `../` splices what surrounds "
              + "it back together, and `....//....//pwnStorage//secret.txt` becomes "
              + "`../../pwnStorage//secret.txt` - a working two-level traversal, manufactured by "
              + "the repair out of a payload that had none. Deleting a substring cannot be a "
              + "defence when deleting it can also create it.")
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "InvalidPathException from the JDK, not from the `../` check.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SECRET_DISCLOSED,
                   "The second bypass: the check looks for a forward slash, so a backslash-"
                 + "separated traversal walks straight past it on the platform where backslash is "
                 + "a separator. Declared for WINDOWS only; POSIX behaviour not yet observed."))
            .build();
    }
}
