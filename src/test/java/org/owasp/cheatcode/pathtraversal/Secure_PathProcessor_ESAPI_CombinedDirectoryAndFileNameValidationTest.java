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

class Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidationTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (ESAPI Combined Directory and File Name Validation)";
    }

    @Override
    String describe() {
        return "Splits the input into directory and filename and validates each with the matching "
             + "ESAPI validator, isValidDirectoryPath being given the base directory as its parent. "
             + "In principle this is the ESAPI approach that should support subdirectories, since "
             + "it validates a directory component rather than forbidding one. In practice it "
             + "scores identically to the filename-only ESAPI variants, because the filename "
             + "validator is applied to the split-off name and the directory half never gets a "
             + "chance to accept it.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, REJECTED,
                "The interesting negative result. This is the one implementation whose design "
              + "anticipates nested paths, and it still cannot serve `SomeSubFolder/sublegit.txt` - "
              + "so the whole ESAPI family loses subdirectory access, not just the filename-only "
              + "members. If any cell in this matrix deserves a follow-up, it is this one.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED)
            .expect(MALFORMED_NULL_BYTE, REJECTED,
                "Rejected by ESAPI rather than by the JDK.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, REJECTED,
                   "Declared for WINDOWS only; POSIX behaviour not yet observed. This "
                 + "implementation splits with java.io.File, so it is one of the more "
                 + "platform-sensitive rows here - File.getParent() answers differently for a "
                 + "backslash-separated string on POSIX."))
            .build();
    }
}
