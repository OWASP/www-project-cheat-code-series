package org.owasp.cheatcode.harness;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

/**
 * What one implementation is declared to do against each payload.
 *
 * <p>Declared per cell rather than per class, because a class-level flag cannot express a
 * partially effective defence — and a partially effective defence is the most instructive
 * thing this project has to show.
 *
 * <p>An expectation declared with {@link Builder#expect(TestPayload, Outcome)} applies on every
 * platform. Add a {@link #on} variant only when the behaviour genuinely differs, and only after
 * observing it on that platform — declaring an outcome you have not seen is guessing, and the
 * whole point of the matrix is that it records observations.
 *
 * <pre>{@code
 * Expectations.builder()
 *     .expect(LEGIT_SIMPLE_FILE, READ_OK)
 *     .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
 *         on(WINDOWS, SANITIZED_MISS),
 *         on(LINUX, UNDETECTED_MISS, "Backslash is a legal filename character on POSIX."))
 *     .build();
 * }</pre>
 */
public final class Expectations {

    private final Map<String, Expectation> defaults;
    private final Map<String, Map<Platform, Expectation>> overrides;

    private Expectations(Map<String, Expectation> defaults,
                         Map<String, Map<Platform, Expectation>> overrides) {
        this.defaults = defaults;
        this.overrides = overrides;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Declares an outcome that applies only on {@code platform}. */
    public static PlatformExpectation on(Platform platform, Outcome outcome) {
        return on(platform, outcome, null);
    }

    /** Declares an outcome that applies only on {@code platform}, with an explanation. */
    public static PlatformExpectation on(Platform platform, Outcome outcome, String note) {
        return new PlatformExpectation(platform, new Expectation(outcome, note));
    }

    /**
     * Looks up the declared expectation for a cell.
     *
     * @return the platform-specific declaration if one exists, otherwise the platform-agnostic
     *         one, otherwise {@code null} — meaning this cell has never been declared and the
     *         test must fail rather than quietly claim coverage it does not have
     */
    public Expectation find(TestPayload payload, Platform platform) {
        Map<Platform, Expectation> perPlatform = overrides.get(payload.id());
        if (perPlatform != null && perPlatform.containsKey(platform)) {
            return perPlatform.get(platform);
        }
        return defaults.get(payload.id());
    }

    /** True if the returned expectation came from a platform-specific declaration. */
    public boolean isPlatformSpecific(TestPayload payload, Platform platform) {
        Map<Platform, Expectation> perPlatform = overrides.get(payload.id());
        return perPlatform != null && perPlatform.containsKey(platform);
    }

    public static final class Builder {

        private final Map<String, Expectation> defaults = new HashMap<>();
        private final Map<String, Map<Platform, Expectation>> overrides = new HashMap<>();

        /** Declares an outcome for this payload on every platform. */
        public Builder expect(TestPayload payload, Outcome outcome) {
            return expect(payload, outcome, null);
        }

        /** Declares an outcome for this payload on every platform, with an explanation. */
        public Builder expect(TestPayload payload, Outcome outcome, String note) {
            rejectDuplicate(payload);
            defaults.put(payload.id(), new Expectation(outcome, note));
            return this;
        }

        /** Declares platform-specific outcomes for this payload. */
        public Builder expect(TestPayload payload, PlatformExpectation... variants) {
            if (variants == null || variants.length == 0) {
                throw new IllegalArgumentException(
                        "at least one platform variant is required for " + payload.id());
            }
            rejectDuplicate(payload);
            Map<Platform, Expectation> perPlatform = new EnumMap<>(Platform.class);
            for (PlatformExpectation variant : variants) {
                if (perPlatform.put(variant.platform(), variant.expectation()) != null) {
                    throw new IllegalArgumentException(
                            "duplicate platform " + variant.platform() + " for " + payload.id());
                }
            }
            overrides.put(payload.id(), perPlatform);
            return this;
        }

        /**
         * Adds platform-specific overrides on top of an already-declared common outcome.
         *
         * <p>Use when one platform is the odd one out and repeating the common case for every
         * other platform would obscure that. Must follow an {@code expect} for the same payload.
         */
        public Builder override(TestPayload payload, PlatformExpectation... variants) {
            if (!defaults.containsKey(payload.id())) {
                throw new IllegalArgumentException(
                        "override without a preceding expect for " + payload.id());
            }
            if (variants == null || variants.length == 0) {
                throw new IllegalArgumentException(
                        "at least one platform variant is required for " + payload.id());
            }
            Map<Platform, Expectation> perPlatform =
                    overrides.computeIfAbsent(payload.id(), k -> new EnumMap<>(Platform.class));
            for (PlatformExpectation variant : variants) {
                if (perPlatform.put(variant.platform(), variant.expectation()) != null) {
                    throw new IllegalArgumentException(
                            "duplicate platform " + variant.platform() + " for " + payload.id());
                }
            }
            return this;
        }

        public Expectations build() {
            return new Expectations(new HashMap<>(defaults), new HashMap<>(overrides));
        }

        private void rejectDuplicate(TestPayload payload) {
            if (defaults.containsKey(payload.id()) || overrides.containsKey(payload.id())) {
                throw new IllegalArgumentException("payload declared twice: " + payload.id());
            }
        }
    }
}
