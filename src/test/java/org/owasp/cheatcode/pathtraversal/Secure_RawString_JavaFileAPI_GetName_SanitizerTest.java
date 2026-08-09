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

class SecurePathProcessor_FileAPI_GetNameTest extends BasePathProcessorTest {

    @Override
    PathProcessor createProcessor(String baseDir) {
        return new SecurePathProcessor_FileAPI_GetName(baseDir);
    }

    @Override
    String getProcessorName() {
        return "Secure Path Processor (FileAPI GetName)";
    }

    @Override
    String describe() {
        return "Uses File.getName() to reduce input to its last path component, and treats input "
             + "as valid only if it already equals that. No pattern to get wrong, and the JDK "
             + "supplies the platform's own idea of what a separator is - which is also what makes "
             + "it the implementation most likely to behave differently on POSIX.";
    }

    @Override
    Expectations expected() {
        return Expectations.builder()
            .expect(LEGIT_SIMPLE_FILE, READ_OK)
            .expect(LEGIT_SUBFOLDER_FILE, SANITIZED_MISS,
                "File.getName() reduces the input to `sublegit.txt`, which does not exist at the "
              + "base directory. Subdirectory access is not merely denied here - it is silently "
              + "redirected to a different file, and would have succeeded had a file of that name "
              + "existed at the top level.")
            .expect(ATTACK_SINGLE_LEVEL_TRAVERSAL, SANITIZED_MISS,
                "Reduced to `secret.txt`, looked for under the base directory, not found.")
            .expect(ATTACK_DOUBLE_LEVEL_TRAVERSAL, SANITIZED_MISS)
            .expect(ATTACK_DOUBLE_DOT_TRAVERSAL, SANITIZED_MISS)
            .expect(MALFORMED_NULL_BYTE, REJECTED_BY_RUNTIME,
                "File.getName() has no opinion about control characters, so `legit.txt\\0` equals "
              + "its own last component and passes validation untouched. The JDK then rejects the "
              + "path. No defence of this implementation's own.")
            .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
                on(WINDOWS, SANITIZED_MISS,
                   "Windows File treats backslash as a separator, so getName() strips the "
                 + "traversal. On POSIX the whole payload is one legal filename and getName() "
                 + "returns it unchanged, so validation would pass it - a different outcome, not "
                 + "yet observed. Declared for WINDOWS only."))
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
