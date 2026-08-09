package org.owasp.cheatcode.pathtraversal;

import org.junit.jupiter.api.Test;

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

class Vulnerable_None_JavaNIO_PathsGet_NoDefenceTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new Vulnerable_None_JavaNIO_PathsGet_NoDefence(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Vulnerable Path Processor (No Checks)";
    }

    @Override
    String describe() {
        return "The baseline flaw: user input is joined to the base directory and read, with no "
             + "validation and no sanitisation of any kind. Everything else in this project is "
             + "measured against what this one lets through.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, READ_OK,
                "Nested access works, because nothing is checked. Worth noticing next to the "
              + "secure rows: the subdirectory support that the filename-only defences give up is "
              + "real functionality - it is just not worth buying it this way.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, UNDETECTED_MISS,
                "Not detected - nothing here detects anything. The read fails only because one "
              + "level up from the base directory lands in SecureStorage/, one short of the "
              + "secret. Move the fixture and this discloses.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SECRET_DISCLOSED,
                "Two levels up reaches pwnStorage/. The traversal the whole project is about.")
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, UNDETECTED_MISS,
                "A useful non-result: `....//` is built to survive naive stripping of `../`, and "
              + "there is no stripping here to survive. The path resolves to a directory literally "
              + "named `....`, which does not exist. This payload is a weapon against bad "
              + "sanitisers, not against absent ones.")
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "Paths.get throws InvalidPathException on the embedded NUL. The JDK stopped this, "
              + "not the implementation - which contains no validation at all. Recorded as a near "
              + "miss so the matrix never shows it as a defence.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SECRET_DISCLOSED,
                   "Backslash is a separator on Windows, so this traverses and discloses. On POSIX "
                 + "a backslash is an ordinary filename character, making the payload one long "
                 + "legal filename that does not exist. Declared for WINDOWS only: that other "
                 + "outcome has not been observed yet, and a Linux run should report it as "
                 + "undeclared rather than as a regression."))
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
