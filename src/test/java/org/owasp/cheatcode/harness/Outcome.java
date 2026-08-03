package org.owasp.cheatcode.harness;

/**
 * What actually happened when a payload was fed to an implementation.
 *
 * <p>This is deliberately richer than pass/fail. A pass/fail verdict cannot distinguish
 * "the implementation rejected the input" from "the implementation silently rewrote the
 * input into a filename that does not exist", and those are very different stories to
 * tell a developer choosing a remediation.
 *
 * <p>An {@code Outcome} carries no judgement on its own — see {@link Verdict}, which
 * interprets it in the light of what the payload was trying to do.
 */
public enum Outcome {

    /** A read succeeded and returned the content the payload legitimately asks for. */
    READ_OK,

    /** A read succeeded and returned the secret. The payload won. */
    SECRET_DISCLOSED,

    /** A read succeeded but returned neither the expected content nor the secret. */
    READ_UNEXPECTED,

    /**
     * The implementation detected the input as hostile and refused to repair it,
     * because it sets {@code canSanitize = false}.
     */
    REJECTED,

    /** The implementation detected the input, attempted a repair, and the repair itself threw. */
    SANITIZE_FAILED,

    /**
     * The implementation detected the input and repaired it, but the repaired path points at
     * a file that does not exist. The attack is blocked; so is any legitimate use of the same
     * shape of input.
     */
    SANITIZED_MISS,

    /** The implementation detected the input, repaired it, and the repaired read succeeded safely. */
    SANITIZED_HIT,

    /**
     * The implementation did <em>not</em> detect the input, and the read failed anyway — because
     * of where the fixture happens to put its files, not because of anything the implementation did.
     *
     * <p>A near miss, not a defence. Reported separately precisely so it is never mistaken for one.
     */
    UNDETECTED_MISS,

    /**
     * The JDK or the filesystem refused the path before any read was attempted — for example
     * {@code InvalidPathException} on an embedded NUL.
     *
     * <p>Also not a defence: the implementation contributed nothing, and the same code on a
     * platform with laxer path parsing would have no protection at all.
     */
    REJECTED_BY_RUNTIME,

    /** Anything else. Always worth looking at. */
    UNEXPECTED_ERROR
}
