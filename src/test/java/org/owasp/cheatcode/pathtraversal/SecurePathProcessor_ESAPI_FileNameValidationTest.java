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

class SecurePathProcessor_ESAPI_FileNameValidationTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_ESAPI_FileNameValidation(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (ESAPI File Name Validation, extensions from ESAPI.properties)";
    }

    @Override
    String describe() {
        return "OWASP ESAPI's filename validator, with both the accepted pattern "
             + "(Validator.FileName) and the allowed extensions "
             + "(HttpUtilities.ApprovedUploadExtensions) read from ESAPI.properties, so policy "
             + "changes without recompiling. Reaches the same verdicts as the hard-coded variant "
             + "by a different route - keeping both is the point.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, REJECTED,
                "Rejected because a separator is not in Validator.FileName, then getValidFileName "
              + "throws rather than returning a repaired name. ESAPI is designed to refuse rather "
              + "than repair, so the caller gets a ValidationException - a cleaner failure than "
              + "the silent rewrite the regex processors perform, but nested access is still lost. "
              + "Note the route: this row reaches REJECTED through a repair attempt that threw, "
              + "where RelativePath_Validation reaches it by never attempting one. Same outcome to "
              + "a caller, different code; the evidence pane's exception class tells them apart.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED,
                "The configured filename pattern has no separator in it, so the payload never "
              + "reaches a path operation at all.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED)
            .expect(MALFORMED_NULL_BYTE, REJECTED,
                "A NUL is outside the configured pattern, so ESAPI rejects it before the JDK gets "
              + "the chance - a real defence rather than a REJECTED_BY_RUNTIME near miss.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, REJECTED,
                   "Backslash is outside the configured filename pattern. Declared for WINDOWS "
                 + "only; POSIX behaviour not yet observed. Since this check is a character "
                 + "pattern rather than a path operation, it is among the more likely to be "
                 + "platform-independent - but that has to be observed, not assumed."))
            .build();
    }
}
