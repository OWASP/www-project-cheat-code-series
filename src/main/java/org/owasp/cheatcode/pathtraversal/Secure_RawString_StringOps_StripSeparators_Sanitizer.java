package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

/**
 * This class contains a secure path processing implementation
 * that uses simple string validation.
 */
public class Secure_RawString_StringOps_StripSeparators_Sanitizer extends PathProcessor {

    public Secure_RawString_StringOps_StripSeparators_Sanitizer(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Deny-list: anything that could name a directory is removed. That blocks every
        // traversal payload, and it also blocks `SomeSubFolder/sublegit.txt` - the cost of
        // reducing input to a bare filename, paid whether the caller was attacking or not.
        //
        // Repaired rather than refused, which is the interesting part: the caller gets no
        // error, just the contents of a different file - or, as here, a NoSuchFileException
        // for a filename nobody asked for. The removals run unconditionally; asking
        // `contains(..)` first, as this used to, gates a repair that is already a no-op when
        // the answer is no.
        //
        // Compare Secure_RawString_Regex_DenySeparators_Sanitizer, which reaches every
        // one of the same outcomes with the rule stated once instead of three times.
        String fileName = userInput.replace("..", "")
                                   .replace("/", "")
                                   .replace("\\", "");

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
