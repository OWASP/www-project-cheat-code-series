package org.owasp.cheatcode.pathtraversal;

import org.junit.jupiter.api.Test;

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

class SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDotTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_RegexValidation_Whitelist_AlphaNumericDot(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (Regex Validation Whitelist)";
    }

    @Override
    String describe() {
        return "Allows only `[a-zA-Z0-9.]`. The structurally strongest filter here: it does not "
             + "enumerate what is dangerous, so it cannot be beaten by a character nobody thought "
             + "of - which is why it handles the null byte that the two blacklists of the same "
             + "shape miss. It also rejects hyphens, spaces and every non-ASCII filename.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, SANITIZED_MISS,
                "A separator is not in the allowed set, so nested access is impossible by "
              + "construction. Stripping it yields a filename that does not exist.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, SANITIZED_MISS)
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SANITIZED_MISS)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, SANITIZED_MISS)
            .expect(MALFORMED_NULL_BYTE, SANITIZED_HIT,
                "Handled by the implementation, with no rule mentioning NUL anywhere: a NUL is "
              + "simply not on the allow-list, so it is rejected and stripped, and `legit.txt` is "
              + "served. This is the concrete argument for allow-lists over deny-lists - the two "
              + "blacklists with otherwise identical verdicts both fall through to the JDK here.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SANITIZED_MISS,
                   "Backslash is not on the allow-list. Declared for WINDOWS only; POSIX "
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
