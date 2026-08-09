package org.owasp.cheatcode.pathtraversal;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opentest4j.AssertionFailedError;

import org.owasp.cheatcode.harness.CellResult;
import org.owasp.cheatcode.harness.Discipline;
import org.owasp.cheatcode.harness.Expectation;
import org.owasp.cheatcode.harness.Expectations;
import org.owasp.cheatcode.harness.Outcome;
import org.owasp.cheatcode.harness.Platform;
import org.owasp.cheatcode.harness.ResultRecorder;
import org.owasp.cheatcode.harness.Verdict;

/**
 * The whole path traversal test harness: seven payloads, scored identically against every
 * implementation.
 *
 * <p>A concrete test class supplies three things — the processor to build, a display name, and
 * {@link #expected()}, which declares what that processor does against each payload. It declares
 * no payloads and no assertions of its own. A payload belongs in {@link Payload} plus one
 * {@code @Test} here, so that adding one re-scores every existing implementation at once.
 *
 * <p>Each concrete class does re-declare these seven methods, as {@code @Test @Override} stubs
 * calling {@code super}, folded into a {@code // #region} at the end of the file. They change
 * nothing about the run; they exist because the VS Code Test Explorer discovers only methods a
 * class declares, never one it inherits. A new payload therefore needs a stub in all fifteen
 * classes as well as a {@code @Test} here — see {@code .design_docs/test_run_options.md}.
 *
 * <h2>Green means "matches what was recorded", not "nothing is vulnerable"</h2>
 *
 * A vulnerable implementation that discloses the secret is a <em>passing</em> test, because
 * disclosure is what it was declared to do. A red test means reality diverged from the record:
 * either a change moved an implementation, or a new payload has never been declared. Both need a
 * human to look.
 *
 * <p><strong>Never edit an expectation just to make a run green.</strong> The matrix diff is the
 * reviewable artifact; changing a declared outcome without the evidence to justify it is exactly
 * the failure this design exists to prevent.
 *
 * <h2>Debugging one case</h2>
 *
 * Every test method is a one-line call to {@link #assertCell}, which is written as a sequence of
 * separate locals rather than a chain. Put a breakpoint on the {@code processor.readFile} line and
 * debug one case — from the stub in the concrete test class, not from here. This class is
 * abstract, so its own gutter icons resolve to no tests at all. Step <em>over</em> to watch the
 * payload become a {@link ReadFileResult}, then an {@link Outcome}, then a comparison; step
 * <em>into</em> for the part worth seeing — the implementation's own {@code getResource}, which
 * holds the entire technique in one method.
 */
@DisplayName("Path Processor Tests")
abstract class BasePathProcessorTest {

    private static final String VULNERABILITY_CLASS = "path-traversal";
    private static final int CONTENT_PREVIEW_LIMIT = 120;

    @TempDir
    protected Path tempDir;

    protected PathProcessor processor;
    private PathTraversalFixture fixture;
    private Expectations expectations;

    /** Builds the implementation under test, rooted at the fixture's base directory. */
    abstract PathProcessor createProcessor(String baseDir);

    /** Human-readable name for this implementation, used in the generated report. */
    abstract String getProcessorName();

    /**
     * What this implementation is declared to do against each payload.
     *
     * <p>Abstract on purpose: a new implementation cannot be added without someone stating what
     * it does. Run it first, read the observed outcomes, then declare them — an expectation
     * written before the run is a guess, and the matrix exists to record observations.
     */
    abstract Expectations expected();

    /**
     * One or two sentences on the technique this implementation demonstrates. Shown in the report
     * alongside the row. Optional, but a row without one is a row a reader has to reverse-engineer.
     */
    String describe() {
        return null;
    }

    @BeforeEach
    void setUp() throws IOException {
        fixture = PathTraversalFixture.create(tempDir);
        processor = createProcessor(fixture.baseDirectory().toString());
        expectations = expected();
    }

    @Test
    void LegitCase_NormalFileName_ShouldReadFile() {
        assertCell(Payload.LEGIT_SIMPLE_FILE);
    }

    @Test
    void EdgeLegitCase_RelativePath_ShouldReadSubfolderLegitFile() {
        assertCell(Payload.LEGIT_SUBFOLDER_FILE);
    }

    @Test
    void AttackCase_SingleLevelTraversal() {
        assertCell(Payload.ATTACK_SINGLE_LEVEL_TRAVERSAL);
    }

    @Test
    void AttackCase_DoubleLevelTraversal() {
        assertCell(Payload.ATTACK_DOUBLE_LEVEL_TRAVERSAL);
    }

    @Test
    void AttackCase_DoubleDotTraversal() {
        assertCell(Payload.ATTACK_DOUBLE_DOT_TRAVERSAL);
    }

    @Test
    void AttackCase_WindowsStylePathTraversal() {
        assertCell(Payload.ATTACK_WINDOWS_STYLE_TRAVERSAL);
    }

    @Test
    void MalformedCase_NullCharacterInput() {
        assertCell(Payload.MALFORMED_NULL_BYTE);
    }

    /**
     * Runs one payload against the implementation, records the cell, and compares what happened
     * with what was declared.
     *
     * <p>The cell is recorded <em>before</em> the assertion, so that a mismatch still reaches the
     * report instead of disappearing into a stack trace.
     */
    protected void assertCell(Payload payload) {
        Platform platform = Platform.current();

        ReadFileResult result = processor.readFile(payload.literal());
        Outcome actual = OutcomeClassifier.classify(payload, result);
        Verdict verdict = Verdict.of(payload.kind(), actual);
        Expectation expectation = expectations.find(payload, platform);

        record(payload, platform, result, actual, verdict, expectation);

        assertDisciplineHolds(payload, result, actual);

        if (expectation == null) {
            throw new AssertionFailedError(undeclaredMessage(payload, platform, result, actual, verdict));
        }

        assertEquals(expectation.outcome(), actual,
                () -> mismatchMessage(payload, platform, result, actual, verdict, expectation));
    }

    /**
     * Checks the implementation against the discipline its own class name claims.
     *
     * <p>Orthogonal to the outcome matrix, and a different kind of failure: the matrix asks
     * "did this change?", while this asks "does the code do what it is filed under?". A class
     * named {@code _Validator} that rewrites input is mis-shelved in the report and mis-taught
     * to anyone reading the tree - and it is the exact defect behind the {@code ....//} breach,
     * where a check fires and a repair runs anyway.
     *
     * <p>Fails ahead of the outcome assertion on purpose. An implementation whose discipline is
     * wrong will usually also produce a surprising outcome, and the discipline message names the
     * cause where the outcome message can only name the symptom.
     */
    private void assertDisciplineHolds(Payload payload, ReadFileResult result, Outcome actual) {
        Discipline discipline = Discipline.fromClassName(processor.getClass().getSimpleName());
        if (discipline == null) {
            return;
        }

        Boolean rewritten = result == null ? null : OutcomeClassifier.inputRewritten(result);
        String violation = discipline.violatedBy(actual, rewritten);
        if (violation == null) {
            return;
        }

        throw new AssertionFailedError(
                "DISCIPLINE VIOLATION"
              + "\n\n  " + processor.getClass().getSimpleName()
              + "\n  is " + violation
              + "\n\n  payload        : " + payload.display()
              + "\n  outcome        : " + actual
              + "\n  input rewritten: " + rewritten
              + "\n\nEither the implementation changed, or the last slot of its class name is "
              + "wrong."
              + "\nFix whichever is actually wrong - do not rename the class just to silence "
              + "this.");
    }

    // -- reporting -----------------------------------------------------------

    private void record(Payload payload, Platform platform, ReadFileResult result,
                        Outcome actual, Verdict verdict, Expectation expectation) {
        CellResult cell = new CellResult();
        cell.vulnerabilityClass = VULNERABILITY_CLASS;

        cell.platform = platform.name();
        cell.osName = System.getProperty("os.name");
        cell.javaVersion = System.getProperty("java.version");

        cell.implementation = processor.getClass().getSimpleName();
        cell.implementationLabel = getProcessorName();
        cell.implementationNote = describe();
        cell.vulnerableByDesign = cell.implementation.startsWith("Vulnerable");

        Discipline discipline = Discipline.fromClassName(cell.implementation);
        cell.discipline = discipline == null ? null : discipline.name();

        cell.payloadId = payload.id();
        cell.payloadLiteral = payload.literal();
        cell.payloadDisplay = payload.display();
        cell.payloadShortLabel = payload.shortLabel();
        cell.payloadKind = payload.kind().name();
        cell.payloadDescription = payload.description();
        cell.payloadSource = payload.source();
        cell.payloadOrdinal = payload.ordinal();

        cell.actualOutcome = actual.name();
        cell.verdict = verdict.name();
        cell.expectedOutcome = expectation == null ? null : expectation.outcome().name();
        cell.note = expectation == null ? null : expectation.note();
        cell.platformSpecificExpectation = expectations.isPlatformSpecific(payload, platform);
        cell.status = expectation == null
                ? CellResult.UNDECLARED
                : (expectation.outcome() == actual ? CellResult.MATCH : CellResult.MISMATCH);

        if (result != null) {
            cell.evidence.inputRewritten = OutcomeClassifier.inputRewritten(result);
            cell.evidence.resolvedPath = relativiseToFixture(result.resolvedPath);
            cell.evidence.contentPreview = preview(result.fileReadResult);
            if (result.fileReadException != null) {
                cell.evidence.exceptionClass = result.fileReadException.getClass().getName();
                cell.evidence.exceptionMessage = result.fileReadException.getMessage();
            }
        }

        ResultRecorder.record(cell);
    }

    /**
     * Strips the {@code @TempDir} prefix so the recorded path is stable across runs and machines —
     * otherwise every cell in the report differs on every run and the diff is useless.
     */
    private String relativiseToFixture(Path path) {
        if (path == null) {
            return null;
        }
        String text = path.toString();
        String root = tempDir.toString();
        return text.startsWith(root) ? "<tempDir>" + text.substring(root.length()) : text;
    }

    private static String preview(String content) {
        if (content == null) {
            return null;
        }
        String trimmed = content.length() > CONTENT_PREVIEW_LIMIT
                ? content.substring(0, CONTENT_PREVIEW_LIMIT) + "..."
                : content;
        return trimmed.replace("\0", "\\0").replace("\n", "\\n").replace("\r", "\\r");
    }

    // -- failure messages ----------------------------------------------------

    private String undeclaredMessage(Payload payload, Platform platform, ReadFileResult result,
                                     Outcome actual, Verdict verdict) {
        return header(payload, platform)
             + "\n  no expectation has been declared for this payload on this platform."
             + "\n"
             + observed(result, actual, verdict)
             + "\n\nCheck that the observed outcome is actually correct, then declare it in "
             + "expected() in this class:"
             + "\n    .expect(Payload." + payload.id() + ", Outcome." + actual.name() + ","
             + "\n        \"why this implementation behaves this way against this payload\")"
             + "\n\nIf the behaviour differs by platform, declare the variants instead:"
             + "\n    .expect(Payload." + payload.id() + ", on(" + platform.name()
             + ", Outcome." + actual.name() + "), on(...))";
    }

    private String mismatchMessage(Payload payload, Platform platform, ReadFileResult result,
                                   Outcome actual, Verdict verdict, Expectation expectation) {
        StringBuilder message = new StringBuilder(header(payload, platform));
        message.append("\n  declared : ").append(expectation.outcome());
        if (expectations.isPlatformSpecific(payload, platform)) {
            message.append("  (declared specifically for ").append(platform).append(')');
        }
        message.append('\n').append(observed(result, actual, verdict));
        if (expectation.note() != null) {
            message.append("\n\n  declared because: ").append(expectation.note());
        }
        message.append("\n\nSomething moved. Either a change altered this implementation's "
                     + "behaviour, or the declaration was wrong."
                     + "\nIf the new behaviour is correct, update the expectation in this class "
                     + "and update its note with it."
                     + "\nNever edit an expectation just to make the run green.");
        return message.toString();
    }

    private String header(Payload payload, Platform platform) {
        return processor.getClass().getSimpleName() + " / " + payload.id()
             + " on " + platform
             + "\n  payload  : \"" + payload.display() + '"';
    }

    private String observed(ReadFileResult result, Outcome actual, Verdict verdict) {
        StringBuilder text = new StringBuilder("  observed : " + actual + "  (verdict " + verdict + ')');
        if (result == null) {
            return text.append("\n  evidence : none - readFile returned null").toString();
        }
        text.append("\n  evidence : rewritten=").append(OutcomeClassifier.inputRewritten(result))
            .append("\n             path=").append(relativiseToFixture(result.resolvedPath));
        if (result.fileReadResult != null) {
            text.append("\n             content=\"").append(preview(result.fileReadResult)).append('"');
        }
        if (result.fileReadException != null) {
            text.append("\n             threw=").append(result.fileReadException.getClass().getSimpleName())
                .append(": ").append(result.fileReadException.getMessage());
        }
        return text.toString();
    }
}
