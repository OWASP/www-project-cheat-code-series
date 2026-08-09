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

class Secure_RawString_Regex_AllowAlphaNumericDot_ValidatorTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new Secure_RawString_Regex_AllowAlphaNumericDot_Validator(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure — alphanumeric allow-list, applied as a validator";
    }

    @Override
    String describe() {
        return "Allows only `[a-zA-Z0-9.]`, and refuses everything else outright. The "
             + "implementation to copy into production: an allow-list cannot be beaten by a "
             + "character nobody thought of, and refusing rather than repairing means the file "
             + "served is always the file named. The cost is real and visible in this row - bare "
             + "filenames only, no subdirectories, no spaces or hyphens - but it is paid loudly.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, REJECTED,
                "The cost, stated plainly. A separator is not on the allow-list, so nested "
              + "access is impossible by construction and the caller is told so. Compare what "
              + "the sanitizer form of this same rule did with the same input: it stripped the "
              + "separator and read `SomeSubFoldersublegit.txt` - a file nobody named, no error "
              + "raised. Same functionality lost, one of them silently.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, REJECTED)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, REJECTED,
                "No rule here mentions `../`, `....//` or any other traversal spelling. A dot is "
              + "allowed and a slash is not, so the payload fails the allow-list without anyone "
              + "having anticipated its shape. This is what 'cannot be beaten by a character "
              + "nobody thought of' means in practice.")
            .expect(MALFORMED_NULL_BYTE, REJECTED,
                "Refused by this implementation, not by the JDK - the one row where that "
              + "difference is worth the whole class. Every deny-list here scores "
              + "REJECTED_BY_RUNTIME on this payload, which means their defence is the "
              + "platform's and would not survive a laxer one. A NUL is simply not on the "
              + "allow-list, so this class carries its own defence anywhere it runs.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, REJECTED,
                   "Backslash is not on the allow-list. Unlike every other row for this payload "
                 + "the result should not actually be platform-dependent - the check never "
                 + "consults the filesystem - but only Windows has been observed, so only "
                 + "Windows is declared."))
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
