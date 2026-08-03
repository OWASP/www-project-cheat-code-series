package org.owasp.cheatcode.pathtraversal;

import org.owasp.cheatcode.harness.PayloadKind;
import org.owasp.cheatcode.harness.TestPayload;

/**
 * Every input each path traversal implementation is scored against.
 *
 * <p>Adding a constant here plus a matching {@code @Test} in {@link BasePathProcessorTest} scores
 * every existing implementation against the new payload at once. Expect it to turn rows red: each
 * implementation will report {@code UNDECLARED} until someone looks at what it actually did and
 * writes that down. Looking at the results before declaring them <em>is</em> the review step.
 *
 * <p><strong>Literals only.</strong> {@link #LEGIT_SUBFOLDER_FILE} used to be built with
 * {@code File.separator}, which quietly made it a different payload on Windows than on Linux —
 * so the same matrix row was comparing two different inputs. Never reintroduce that.
 */
enum Payload implements TestPayload {

    LEGIT_SIMPLE_FILE(
            "legit.txt",
            "legit.txt",
            PayloadKind.LEGITIMATE,
            PathTraversalFixture.PUBLIC_FILE_CONTENT,
            "A plain filename directly in the base directory. The control case: any implementation "
          + "that cannot serve this is broken rather than strict.",
            null),

    LEGIT_SUBFOLDER_FILE(
            "SomeSubFolder/sublegit.txt",
            "SomeSubFolder/…",
            PayloadKind.LEGITIMATE,
            PathTraversalFixture.SUBFOLDER_CONTENT,
            "Legitimate access to a file one level down. This is the payload that prices each "
          + "remediation: every defence that reduces input to a bare filename blocks all six "
          + "attacks and loses this too.",
            null),

    ATTACK_SINGLE_LEVEL_TRAVERSAL(
            "../pwnStorage/secret.txt",
            "../",
            PayloadKind.ATTACK,
            null,
            "One level up. In this fixture it lands one directory short of the secret, so an "
          + "implementation that ignores it is not punished by a disclosure - which is exactly "
          + "why the outcome is recorded as a near miss rather than a pass.",
            null),

    ATTACK_DOUBLE_LEVEL_TRAVERSAL(
            "../../pwnStorage/secret.txt",
            "../../",
            PayloadKind.ATTACK,
            null,
            "Two levels up, which in this fixture reaches the secret. The simplest payload that "
          + "actually discloses data.",
            null),

    ATTACK_DOUBLE_DOT_TRAVERSAL(
            "....//....//pwnStorage//secret.txt",
            "....//",
            PayloadKind.ATTACK,
            null,
            "Defeats naive stripping: a filter that deletes occurrences of `../` turns `....//` "
          + "back into `../`, reassembling the traversal it just removed. The classic argument "
          + "against sanitising by deletion.",
            "PayloadsAllTheThings - Directory Traversal"),

    ATTACK_WINDOWS_STYLE_TRAVERSAL(
            "..\\..\\pwnStorage\\secret.txt",
            "..\\..\\",
            PayloadKind.ATTACK,
            null,
            "Backslash separators. Genuinely platform-dependent: on Windows these are separators "
          + "and the payload traverses, while on POSIX a backslash is an ordinary filename "
          + "character, so the same string is one long legal filename that simply does not exist.",
            null),

    MALFORMED_NULL_BYTE(
            "legit.txt\0",
            "\\0",
            PayloadKind.MALFORMED,
            PathTraversalFixture.PUBLIC_FILE_CONTENT,
            "A trailing NUL, historically used to truncate a filename past an extension check. "
          + "Modern JVMs reject an embedded NUL in Paths.get, so most implementations survive this "
          + "without containing any code that looks at it - recorded as REJECTED_BY_RUNTIME so the "
          + "matrix does not credit the implementation for the platform's work.",
            null);

    private final String literal;
    private final String shortLabel;
    private final PayloadKind kind;
    private final String expectedContent;
    private final String description;
    private final String source;

    Payload(String literal, String shortLabel, PayloadKind kind, String expectedContent,
            String description, String source) {
        this.literal = literal;
        this.shortLabel = shortLabel;
        this.kind = kind;
        this.expectedContent = expectedContent;
        this.description = description;
        this.source = source;
    }

    /** A few characters identifying the payload, used as a column heading in the matrix. */
    String shortLabel() {
        return shortLabel;
    }

    @Override
    public String id() {
        return name();
    }

    @Override
    public String literal() {
        return literal;
    }

    @Override
    public PayloadKind kind() {
        return kind;
    }

    @Override
    public String expectedContent() {
        return expectedContent;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public String source() {
        return source;
    }

    /** The literal with control characters made visible, for display in reports and messages. */
    String display() {
        StringBuilder out = new StringBuilder(literal.length() + 4);
        for (char c : literal.toCharArray()) {
            if (c == '\0') {
                out.append("\\0");
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '\r') {
                out.append("\\r");
            } else if (c == '\t') {
                out.append("\\t");
            } else if (c < 0x20 || c == 0x7f) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
