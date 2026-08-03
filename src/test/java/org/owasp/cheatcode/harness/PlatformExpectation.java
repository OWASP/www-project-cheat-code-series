package org.owasp.cheatcode.harness;

/**
 * An expectation that applies only on one platform.
 *
 * <p>Built with {@link Expectations#on}. Only declare one of these when the behaviour genuinely
 * differs — an unnecessary platform split turns one reviewable row into several that drift apart.
 */
public final class PlatformExpectation {

    private final Platform platform;
    private final Expectation expectation;

    PlatformExpectation(Platform platform, Expectation expectation) {
        this.platform = platform;
        this.expectation = expectation;
    }

    Platform platform() {
        return platform;
    }

    Expectation expectation() {
        return expectation;
    }
}
