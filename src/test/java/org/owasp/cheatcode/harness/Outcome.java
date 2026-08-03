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
 *
 * <p>"Rewrote the input" is observed, not self-reported: it means the implementation read from
 * a different path than the raw input names. An implementation that runs a repair which happens
 * to change nothing therefore does not count as having rewritten anything, which is the honest
 * answer — nothing about the file it read was affected by the repair.
 */
public enum Outcome {

    /** A read succeeded and returned the content the payload legitimately asks for. */
    READ_OK,

    /** A read succeeded and returned the secret. The payload won. */
    SECRET_DISCLOSED,

    /** A read succeeded but returned neither the expected content nor the secret. */
    READ_UNEXPECTED,

    /**
     * The caller got an exception instead of content, and the JDK's path parser was not the
     * reason. The implementation refused the input — either by rejecting it outright, or by
     * attempting a repair that threw rather than returning a repaired name.
     *
     * <p>Those two used to be separate values. They are one now because they are one thing from
     * where the caller stands: no file was named, and an exception came back. Which route was
     * taken is visible in the recorded exception class, and in the implementation's own code.
     */
    REJECTED,

    /**
     * The implementation rewrote the input, and the rewritten path points at a file that does
     * not exist. The attack is blocked; so is any legitimate use of the same shape of input.
     */
    SANITIZED_MISS,

    /** The implementation rewrote the input, and the read of the rewritten path succeeded safely. */
    SANITIZED_HIT,

    /**
     * The implementation read from exactly the path the raw input names — it changed nothing —
     * and the read failed anyway, because of where the fixture happens to put its files rather
     * than because of anything the implementation did.
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
