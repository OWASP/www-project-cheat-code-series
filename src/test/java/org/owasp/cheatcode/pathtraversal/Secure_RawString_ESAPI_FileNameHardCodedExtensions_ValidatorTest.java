package org.owasp.cheatcode.pathtraversal;

import org.junit.jupiter.api.Test;

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
            .expect(LEGIT_SUBFOLDER_FILE, REJECTED,
                "A separator fails the filename pattern and getValidFileName throws rather than "
              + "repairing. Nested access is lost, with a clear exception rather than a silent "
              + "rewrite - the caller can tell it was refused, which the rewriting processors "
              + "never let them find out.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED)
            .expect(MALFORMED_NULL_BYTE, REJECTED,
                "Rejected by ESAPI's pattern before the JDK sees the path - a genuine defence, "
              + "unlike the seven implementations that record REJECTED_BY_RUNTIME here.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, REJECTED,
                   "Backslash fails the filename pattern. Declared for WINDOWS only; POSIX "
                 + "behaviour not yet observed."))
            .build();
    }

    // #region Seven stubs so each case is runnable on its own - see .design_docs/test_run_options.md
    //
    // Every method below is already inherited from BasePathProcessorTest and adds nothing to the
    // run: delete the whole block and the test count and every assertion stay exactly the same.
    // They are here because the VS Code Test Explorer only discovers methods a class *declares*,
    // never one it inherits, so without them "Debug Test" on a single case launches all seven.

    @Test
    @Override
    void LegitCase_NormalFileName_ShouldReadFile() {
        super.LegitCase_NormalFileName_ShouldReadFile();
    }

    @Test
    @Override
    void EdgeLegitCase_RelativePath_ShouldReadSubfolderLegitFile() {
        super.EdgeLegitCase_RelativePath_ShouldReadSubfolderLegitFile();
    }

    @Test
    @Override
    void AttackCase_SingleLevelTraversal() {
        super.AttackCase_SingleLevelTraversal();
    }

    @Test
    @Override
    void AttackCase_DoubleLevelTraversal() {
        super.AttackCase_DoubleLevelTraversal();
    }

    @Test
    @Override
    void AttackCase_DoubleDotTraversal() {
        super.AttackCase_DoubleDotTraversal();
    }

    @Test
    @Override
    void AttackCase_WindowsStylePathTraversal() {
        super.AttackCase_WindowsStylePathTraversal();
    }

    @Test
    @Override
    void MalformedCase_NullCharacterInput() {
        super.MalformedCase_NullCharacterInput();
    }

    // #endregion
}
