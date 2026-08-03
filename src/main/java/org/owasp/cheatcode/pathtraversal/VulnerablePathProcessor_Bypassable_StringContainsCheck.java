package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a vulnerable path processing implementation
 * that performs only a simple string contains check.
 *
 * <p>It genuinely blocks the obvious payloads and falls to the ones written to beat it, which
 * makes it the most instructive implementation here: it shows that "does it validate?" is the
 * wrong question, and "what exactly does it validate, and what does it do when the check fires?"
 * is the right one.
 */
public class VulnerablePathProcessor_Bypassable_StringContainsCheck extends PathProcessor {

    public VulnerablePathProcessor_Bypassable_StringContainsCheck(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        String fileName = userInput;

        // Vulnerable: one substring, one shape of traversal. A backslash-separated payload
        // (`..\..\`) contains no forward slash and walks straight past this check.
        if (fileName.contains("../")) {
            // Vulnerable: repair by deletion. Deleting `../` out of `....//` splices the
            // surrounding characters together into a fresh `../` - the check fires, the repair
            // runs, and the result is the traversal the check was looking for.
            fileName = fileName.replace("../", "");
        }

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
