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

class VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalNameTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (FileAPI MultipartFile)";
    }

    @Override
    String describe() {
        return "Treats Spring's MultipartFile.getOriginalFilename() as though it sanitised the "
             + "name. It does not - it returns whatever the client sent, path components included. "
             + "The most realistic flaw in this project, because the code reads as though a "
             + "framework API is doing the validating.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK)
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, UNDETECTED_MISS,
                "getOriginalFilename() returns the payload unchanged, so validation - which "
              + "compares the two - sees no difference and reports the input as clean. The read "
              + "then fails only on the fixture layout.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SECRET_DISCLOSED,
                "The framework API returned the traversal untouched and the secret is disclosed.")
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, UNDETECTED_MISS,
                "Passed through unchanged, then resolves to a nonexistent `....` directory.")
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "InvalidPathException from the JDK. getOriginalFilename() happily returned the "
              + "NUL-terminated name.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SECRET_DISCLOSED,
                   "Backslash is a separator on Windows - and a backslash-separated name is "
                 + "exactly what a Windows browser historically put in this field, which is what "
                 + "makes this the realistic case. Declared for WINDOWS only; POSIX behaviour not "
                 + "yet observed."))
            .build();
    }
}
