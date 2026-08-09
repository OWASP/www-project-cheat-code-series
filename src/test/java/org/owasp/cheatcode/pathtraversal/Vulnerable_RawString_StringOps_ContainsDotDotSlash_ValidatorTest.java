package org.owasp.cheatcode.pathtraversal;

import org.junit.jupiter.api.Test;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.REJECTED;
import static org.owasp.cheatcode.harness.Outcome.REJECTED_BY_RUNTIME;
import static org.owasp.cheatcode.harness.Outcome.SECRET_DISCLOSED;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class Vulnerable_RawString_StringOps_ContainsDotDotSlash_ValidatorTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable — `../` contains-rule, applied as a validator";
    }

    @Override
    String describe() {
        return "Refuses any input containing the literal `../`; reads anything else untouched. "
             + "Compare the Sanitizer row directly below: identical rule, opposite result on "
             + "`....//`. Refusing closes the bypass that repair-by-deletion opens - and leaves "
             + "the other one wide open, because the rule still knows only one spelling of "
             + "traversal.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK,
                "Keeps subdirectory access: the rule looks for `../`, not for separators, so a "
              + "legitimate `SomeSubFolder/` is untouched. The functionality every filename-only "
              + "defence gives up - held here by a class that is still vulnerable.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED,
                "Contains `../`. Refused outright: the caller gets a SecurityException, not the "
              + "contents of some other file.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED,
                "Also contains `../`. Refused.")
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED,
                "The row this class exists for. `....//` does contain a literal `../` - at index "
              + "2 - so the rule fires here exactly as it fires in the Sanitizer twin. The twin "
              + "then deletes it, splicing the surrounding characters into a fresh `../` and "
              + "disclosing the secret. This one just says no. Identical rule, identical payload, "
              + "SECRET_DISCLOSED against REJECTED: the difference is entirely in what follows "
              + "the check.")
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "No `../`, so the check passes the payload through untouched and it is the JDK's "
              + "path parser that refuses it. Not a defence this class contributed.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SECRET_DISCLOSED,
                   "Why refusing does not make this Secure. The rule names a forward slash, so "
                 + "`..\\..\\pwnStorage\\secret.txt` contains no `../`, passes untouched, and "
                 + "traverses on the platform where backslash is a separator. Refusing instead "
                 + "of repairing closes one bypass; it cannot complete an incomplete rule. "
                 + "Declared for WINDOWS only; POSIX behaviour not yet observed."))
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
