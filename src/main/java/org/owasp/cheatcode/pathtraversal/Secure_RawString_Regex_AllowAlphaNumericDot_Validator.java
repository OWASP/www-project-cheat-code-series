package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Secure. Refuses any input that is not entirely letters, digits and dots, then reads what it
 * was given, untouched.
 *
 * <p><strong>The implementation to copy into production.</strong> An allow-list states what is
 * permitted and excludes everything else by omission, so nothing here names traversal,
 * separators, NUL, URL-encoding or any other payload shape - none of them are alphanumeric, so
 * none of them need naming, and no new payload requires a new rule. Combined with refusing
 * rather than repairing, that leaves no bypass to find and no rewritten path to be surprised by.
 *
 * <p>It refuses rather than repairs on purpose. A sanitizer that strips the offending characters
 * would accept {@code SomeSubFolder/sublegit.txt} and quietly read
 * {@code SomeSubFoldersublegit.txt} - a file the caller never named, served with no error
 * anywhere. Refusing costs the same functionality and says so. See the project's design
 * position in CLAUDE.md: validation is the recommendation, sanitization is the fallback.
 *
 * <p>Limitations: bare filenames only. Subdirectory access is refused, and so is any filename
 * containing a space, a hyphen, an underscore or a non-ASCII letter. Widen the character class
 * if the application needs them - but widen it deliberately, one character at a time, and never
 * to include a separator.
 */
public class Secure_RawString_Regex_AllowAlphaNumericDot_Validator extends PathProcessor {

    // The allow-list, anchored at both ends so it must describe the whole input rather than
    // merely occur somewhere inside it. An unanchored allow-list is not an allow-list.
    private static final Pattern ALLOWED = Pattern.compile("^[a-zA-Z0-9.]+$");

    public Secure_RawString_Regex_AllowAlphaNumericDot_Validator(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // Refuse anything the allow-list does not describe. No repair, no second attempt, no
        // rewritten name: the caller either gets the file they asked for or an exception saying
        // they cannot have it. That is the property worth having in production - the set of
        // files this method can return is exactly the set of files a caller can name.
        if (!ALLOWED.matcher(userInput).matches()) {
            throw new SecurityException("Rejected: input is not a bare alphanumeric file name: "
                    + userInput);
        }

        // Read exactly what was validated. Nothing was changed on the way through, so there is
        // no gap between the string that passed the check and the string used to open the file.
        return readFrom(Paths.get(baseDirectory, userInput));
    }
}
