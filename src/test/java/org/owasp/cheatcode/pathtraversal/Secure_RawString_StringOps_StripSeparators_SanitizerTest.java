package org.owasp.cheatcode.pathtraversal;

import org.junit.jupiter.api.Test;

import org.owasp.cheatcode.harness.Expectations;

import static org.owasp.cheatcode.harness.Expectations.on;
import static org.owasp.cheatcode.harness.Outcome.READ_OK;
import static org.owasp.cheatcode.harness.Outcome.REJECTED_BY_RUNTIME;
import static org.owasp.cheatcode.harness.Outcome.SANITIZED_MISS;
import static org.owasp.cheatcode.harness.Platform.WINDOWS;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_DOT_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SIMPLE_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.LEGIT_SUBFOLDER_FILE;
import static org.owasp.cheatcode.pathtraversal.Payload.MALFORMED_NULL_BYTE;

class Secure_RawString_StringOps_StripSeparators_SanitizerTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new Secure_RawString_StringOps_StripSeparators_Sanitizer(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (String Contains Simple)";
    }

    @Override
    String describe() {
        return "Rejects input containing `..`, `/` or `\\` - a blacklist, but a complete enough one "
             + "that no traversal payload here survives it. Then repairs by deleting those "
             + "characters, which is where the cost shows up: repair turns a rejected input into a "
             + "different filename rather than an error.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, SANITIZED_MISS,
                "The price of the defence. Deleting separators turns `SomeSubFolder/sublegit.txt` "
              + "into `SomeSubFoldersublegit.txt` - not a rejection but a silent rewrite into a "
              + "filename that does not exist. A caller gets NoSuchFileException and no hint that "
              + "their input was altered.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, SANITIZED_MISS,
                "Caught by the `..` check, then flattened to a name with no separators left.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SANITIZED_MISS,
                "Caught by the `..` check.")
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, SANITIZED_MISS,
                "Caught. Unlike the bypassable vulnerable variant, this blacklist matches bare "
              + "`..` rather than `../`, so padding the dots does not evade it.")
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "Not caught: a NUL is none of `..`, `/` or `\\`, so validation passes it and the "
              + "JDK rejects the path. This implementation has no null-byte defence of its own - "
              + "the matrix records the platform's work as a near miss rather than crediting it.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SANITIZED_MISS,
                   "Caught by the explicit backslash check. Declared for WINDOWS only, since the "
                 + "POSIX behaviour of this payload has not been observed yet."))
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
