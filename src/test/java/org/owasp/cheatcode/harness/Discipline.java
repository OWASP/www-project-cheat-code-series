package org.owasp.cheatcode.harness;

/**
 * What an implementation does once it holds the untrusted input — the last slot of every
 * implementation's class name.
 *
 * <p>Read from the class name rather than declared separately, on purpose. A second declaration
 * could drift from the name, and then two places would claim different things about one class.
 * This way the name <em>is</em> the claim, and {@link #violatedBy(Outcome, Boolean)} checks that
 * claim against what the implementation was observed to do.
 *
 * <p>The project's position on which to reach for is in CLAUDE.md: validation is what production
 * code should do, sanitization is the fallback for input you are not allowed to refuse. A
 * sanitizer silently changes which file is read, so a caller is never told their request was not
 * honoured.
 */
public enum Discipline {

    /** Refuses by throwing. Never rewrites the input. */
    VALIDATOR,

    /** Rewrites the input unconditionally. Never refuses. */
    SANITIZER,

    /** Neither checks nor repairs. The input reaches the filesystem as it arrived. */
    NO_DEFENCE,

    /**
     * Occupies a sanitizer's position in the code and provides nothing — an API whose name
     * suggests the framework has handled this, which returns the caller's string verbatim.
     *
     * <p>Behaviourally identical to {@link #NO_DEFENCE}; the distinction exists because the
     * matrix cannot express it. Two such implementations score the same on every payload, so if
     * the name does not carry the trap, nothing does.
     */
    FALSE_SANITIZER;

    /**
     * Reads the discipline out of the trailing slot of an implementation's class name.
     *
     * @param simpleClassName e.g. {@code Secure_RawString_Regex_AllowAlphaNumericDot_Validator}
     * @return the declared discipline, or {@code null} for scaffolding that carries no slot
     */
    public static Discipline fromClassName(String simpleClassName) {
        if (simpleClassName == null) {
            return null;
        }
        int lastSlot = simpleClassName.lastIndexOf('_');
        if (lastSlot < 0) {
            return null;
        }
        switch (simpleClassName.substring(lastSlot + 1)) {
            case "Validator":
                return VALIDATOR;
            case "Sanitizer":
                return SANITIZER;
            case "NoDefence":
                return NO_DEFENCE;
            case "FalseSanitizer":
                return FALSE_SANITIZER;
            default:
                return null;
        }
    }

    /**
     * Does this outcome contradict the discipline the class name claims?
     *
     * <p>Catches the bug the {@code ....//} breach is made of: code that says it validates and
     * in fact repairs, so an input the check rejected still reaches the filesystem in some other
     * form. It also catches the reverse — a class named for repair that turns out to throw, whose
     * callers will be handling an exception nobody documented.
     *
     * <p>{@link Outcome#REJECTED_BY_RUNTIME} is never a violation for anyone: that is the JDK's
     * path parser refusing, which no implementation asked for and none can prevent.
     *
     * @param outcome        what happened
     * @param inputRewritten whether the implementation read a path other than the naive join,
     *                       or {@code null} when it never resolved one
     * @return a sentence naming the contradiction, or {@code null} when the two agree
     */
    public String violatedBy(Outcome outcome, Boolean inputRewritten) {
        boolean rewrote = Boolean.TRUE.equals(inputRewritten);
        boolean refused = outcome == Outcome.REJECTED;

        switch (this) {
            case VALIDATOR:
                if (rewrote) {
                    return "named a Validator, but it rewrote the input and read a different path"
                         + " than the one it was given. A validator refuses; it does not repair.";
                }
                return null;
            case SANITIZER:
                if (refused) {
                    return "named a Sanitizer, but it threw instead of returning a repaired name."
                         + " Either it is a Validator, or a repair path is throwing by accident.";
                }
                return null;
            case NO_DEFENCE:
            case FALSE_SANITIZER:
                if (rewrote) {
                    return "named as carrying no defence, but it rewrote the input - so something"
                         + " in it is acting as a sanitizer after all.";
                }
                if (refused) {
                    return "named as carrying no defence, but it refused the input - so something"
                         + " in it is acting as a validator after all.";
                }
                return null;
            default:
                return null;
        }
    }
}
