package org.owasp.cheatcode.harness;

/**
 * What an {@link Outcome} <em>means</em>, given what the payload was trying to do.
 *
 * <p>This is the axis the report colours by. It is orthogonal to whether the test passed:
 * a cell can be a {@link #BREACH} and still be green, because the breach is exactly what
 * the implementation was declared to do. That combination is the whole point of the project.
 */
public enum Verdict {

    /** The implementation did the right thing. */
    SAFE,

    /** The attack was stopped, but legitimate input of the same shape is stopped too. */
    FUNCTIONALITY_LOST,

    /**
     * The attack did not succeed, but the implementation is not why. The fixture layout or
     * the platform stopped it. Move the secret, or change platform, and it lands.
     */
    NEAR_MISS,

    /** The payload reached the secret. */
    BREACH,

    /** Something happened that the harness does not have a story for. */
    ERROR;

    /**
     * Interprets an outcome in the light of the payload that produced it.
     *
     * @param kind    what the payload was trying to do
     * @param outcome what actually happened
     * @return the security meaning of that pairing
     */
    public static Verdict of(PayloadKind kind, Outcome outcome) {
        if (kind == PayloadKind.LEGITIMATE) {
            return outcome == Outcome.READ_OK ? SAFE : FUNCTIONALITY_LOST;
        }

        switch (outcome) {
            case SECRET_DISCLOSED:
                return BREACH;
            case REJECTED:
            case SANITIZED_MISS:
            case SANITIZED_HIT:
                return SAFE;
            case UNDETECTED_MISS:
            case REJECTED_BY_RUNTIME:
                return NEAR_MISS;
            case READ_OK:
                // A malformed payload that names a legitimate file and is served it.
                return kind == PayloadKind.MALFORMED ? SAFE : ERROR;
            default:
                return ERROR;
        }
    }
}
