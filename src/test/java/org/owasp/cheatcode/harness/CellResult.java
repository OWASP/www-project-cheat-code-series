package org.owasp.cheatcode.harness;

/**
 * One cell of the matrix: what one implementation did with one payload on one platform.
 *
 * <p>Serialised to JSON, one file per cell, and read back by the report generator. Fields are
 * public and plain (strings, not enums) on purpose — the wire format is an artifact that
 * outlives any particular run and may be consumed by tooling that does not share these classes.
 *
 * <p>Recorded whether the test passed or failed, so that a mismatch still appears in the report
 * rather than vanishing into a stack trace.
 */
public final class CellResult {

    /** Bumped when the shape of this record changes incompatibly. */
    public int schemaVersion = 3;

    public String vulnerabilityClass;

    // --- provenance ---------------------------------------------------------
    public String platform;
    public String osName;
    public String javaVersion;

    // --- the implementation under test --------------------------------------
    public String implementation;
    public String implementationLabel;
    public String implementationNote;
    public boolean vulnerableByDesign;
    /**
     * What the implementation does once it holds the input — {@code VALIDATOR}, {@code SANITIZER},
     * {@code NO_DEFENCE} or {@code FALSE_SANITIZER}, read from the last slot of the class name.
     *
     * <p>{@code null} only for a class that carries no slot. The suite fails a cell whose observed
     * behaviour contradicts this, so it is a checked claim rather than a label.
     */
    public String discipline;

    // --- the payload --------------------------------------------------------
    public String payloadId;
    /** The exact string handed to the implementation, control characters and all. */
    public String payloadLiteral;
    /** The same string with control characters made visible, for display. */
    public String payloadDisplay;
    /** A few characters identifying the payload, used as a column heading. */
    public String payloadShortLabel;
    public String payloadKind;
    public String payloadDescription;
    public String payloadSource;
    /** Declaration order of the payload, so the report can present columns in the authored order. */
    public int payloadOrdinal;

    // --- the result ---------------------------------------------------------
    /** The declared outcome, or {@code null} if this cell has never been declared. */
    public String expectedOutcome;
    public String actualOutcome;
    public String verdict;
    /** {@code MATCH}, {@code MISMATCH} or {@code UNDECLARED}. */
    public String status;
    /** True if the expectation was declared specifically for this platform rather than for all. */
    public boolean platformSpecificExpectation;
    /** Why the implementation behaves this way against this payload. */
    public String note;

    public Evidence evidence = new Evidence();

    public static final String MATCH = "MATCH";
    public static final String MISMATCH = "MISMATCH";
    public static final String UNDECLARED = "UNDECLARED";

    /** What the harness actually observed, kept so a reader can check the classification. */
    public static final class Evidence {
        /**
         * Whether the implementation read from somewhere other than the naive join of the base
         * directory and the raw input. {@code null} when it never resolved a path at all, so the
         * question does not apply.
         *
         * <p>Derived from {@link #resolvedPath}, not self-reported: schema version 1 carried
         * {@code attackDetected} and {@code pathSanitized} flags that the old base class set on
         * the implementation's behalf, and those no longer exist.
         */
        public Boolean inputRewritten;
        public String resolvedPath;
        public String contentPreview;
        public String exceptionClass;
        public String exceptionMessage;
    }
}
