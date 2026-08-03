package org.owasp.cheatcode.harness;

/**
 * What a payload is trying to do. Determines how an {@link Outcome} is interpreted:
 * a rejection is a success for an {@link #ATTACK} and a functionality loss for a
 * {@link #LEGITIMATE} input.
 */
public enum PayloadKind {

    /** Input a real user would legitimately send. Anything other than a successful read is a cost. */
    LEGITIMATE,

    /** Input crafted to escape the base directory and reach the secret. */
    ATTACK,

    /**
     * Input that is neither legitimate nor a traversal attempt on its own — malformed data
     * used to probe how validation and the platform handle it.
     */
    MALFORMED
}
