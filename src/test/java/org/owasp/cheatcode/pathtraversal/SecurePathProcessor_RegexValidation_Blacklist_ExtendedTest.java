package org.owasp.cheatcode.pathtraversal;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.SANITIZED_HIT;
import static org.owasp.cheatcode.harness.Outcome.SANITIZED_MISS;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class SecurePathProcessor_RegexValidation_Blacklist_ExtendedTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Blacklist_Extended(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Extended)";
    }

    @Override
    String describe() {
        return "A wider blacklist: the characters Windows forbids in filenames, plus leading and "
             + "trailing whitespace, plus an explicit NUL check. Notable as one of only two "
             + "implementations that handle the null-byte payload with their own code rather than "
             + "leaving it to the JDK.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, SANITIZED_MISS,
                "Separators are replaced with underscores rather than deleted, so the input "
              + "becomes `SomeSubFolder_sublegit.txt` - still a silent rewrite into a filename "
              + "that does not exist.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, SANITIZED_MISS)
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SANITIZED_MISS)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, SANITIZED_MISS)
            .expect(MALFORMED_NULL_BYTE, SANITIZED_HIT,
                "The distinguishing cell. The explicit `\\0` check detects the payload, the "
              + "sanitiser strips the NUL, and the resulting `legit.txt` is read successfully. "
              + "The implementation handled this itself - compare the seven implementations that "
              + "record REJECTED_BY_RUNTIME here and are relying on the JDK.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SANITIZED_MISS,
                   "Backslash is in the forbidden set. Declared for WINDOWS only; POSIX behaviour "
                 + "not yet observed."))
            .build();
    }
}
