package org.owasp.cheatcode.harness;

/**
 * A declared outcome for one cell, together with the explanation of why it is that way.
 *
 * <p>The note is not decoration. It is the reason this design keeps commentary here rather
 * than in a documentation file: changing what you expect puts the stale explanation directly
 * under your cursor.
 */
public final class Expectation {

    private final Outcome outcome;
    private final String note;

    Expectation(Outcome outcome, String note) {
        if (outcome == null) {
            throw new IllegalArgumentException("outcome is required");
        }
        this.outcome = outcome;
        this.note = note;
    }

    public Outcome outcome() {
        return outcome;
    }

    /** Why this implementation behaves this way against this payload. May be {@code null}. */
    public String note() {
        return note;
    }
}
