package org.owasp.cheatcode.harness;

/**
 * A single input fed to every implementation of one vulnerability class.
 *
 * <p>Implemented by a per-vulnerability enum, so that payloads stay type-safe and
 * self-documenting while the harness stays free of any knowledge of a particular
 * vulnerability.
 *
 * <p><strong>Payload strings must be literals.</strong> Never build one with
 * {@code File.separator} or any other platform-dependent value: a payload that differs
 * by platform makes the matrix compare two different things while claiming to compare one.
 * If both separators are worth testing, they are two payloads.
 */
public interface TestPayload {

    /** Stable identifier, used as the cell key in the report. Must not change casually. */
    String id();

    /** The exact string handed to the implementation. Always a literal. */
    String literal();

    /** What this payload is trying to do. */
    PayloadKind kind();

    /**
     * The content a correct read of this payload returns, or {@code null} if a correct
     * implementation never returns content for it (i.e. attacks).
     */
    String expectedContent();

    /** One or two sentences on what the payload does and why it is interesting. Shown in the report. */
    String description();

    /** Where the payload came from, or {@code null} if it is original. */
    String source();
}
