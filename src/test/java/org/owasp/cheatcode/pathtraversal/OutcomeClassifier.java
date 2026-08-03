package org.owasp.cheatcode.pathtraversal;

import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;

import org.owasp.cheatcode.harness.Outcome;

/**
 * Turns a {@link ReadFileResult} into the single {@link Outcome} that describes what happened.
 *
 * <p>All the interpretation in the harness lives here, in one function, so that the rules are
 * reviewable in one place and every cell in the matrix is classified identically.
 *
 * <p>Order matters. Disclosure is checked first, because a "sanitiser" that repairs an input
 * into the secret is a breach no matter how well-behaved the rest of the pipeline looked.
 */
final class OutcomeClassifier {

    private OutcomeClassifier() {
    }

    static Outcome classify(Payload payload, ReadFileResult result) {
        if (result == null) {
            return Outcome.UNEXPECTED_ERROR;
        }

        if (result.fileReadResult != null) {
            return classifySuccessfulRead(payload, result);
        }

        Exception failure = result.fileReadException;
        if (failure == null) {
            // No content and no exception: the pipeline returned nothing without saying why.
            return Outcome.UNEXPECTED_ERROR;
        }

        if (failure instanceof UnsupportedOperationException) {
            // canSanitize == false: the implementation detected the input and declined to repair it.
            return Outcome.REJECTED;
        }

        if (isRuntimePathRejection(failure)) {
            // The JDK refused the path before the implementation's logic mattered.
            return Outcome.REJECTED_BY_RUNTIME;
        }

        if (result.isPathSanitized) {
            // Repaired, then the repaired path turned out not to exist.
            return failure instanceof NoSuchFileException
                    ? Outcome.SANITIZED_MISS
                    : Outcome.UNEXPECTED_ERROR;
        }

        if (result.isPathTraversalAttackDetected) {
            // Detected, repair attempted, and the repair itself threw.
            return Outcome.SANITIZE_FAILED;
        }

        // Never detected. If the read failed it is because of where the fixture puts its files,
        // not because of anything the implementation did.
        return failure instanceof NoSuchFileException
                ? Outcome.UNDETECTED_MISS
                : Outcome.UNEXPECTED_ERROR;
    }

    private static Outcome classifySuccessfulRead(Payload payload, ReadFileResult result) {
        if (PathTraversalFixture.SECRET_FILE_CONTENT.equals(result.fileReadResult)) {
            return Outcome.SECRET_DISCLOSED;
        }

        boolean servedWhatWasAskedFor = result.fileReadResult.equals(payload.expectedContent());
        if (!servedWhatWasAskedFor) {
            return Outcome.READ_UNEXPECTED;
        }
        return result.isPathSanitized ? Outcome.SANITIZED_HIT : Outcome.READ_OK;
    }

    /**
     * True when the platform, not the implementation, refused the path.
     *
     * <p>{@link InvalidPathException} is what {@code Paths.get} throws for an embedded NUL on
     * every mainstream JVM. Distinguishing it matters: an implementation that "passes" the
     * null-byte payload this way has no defence of its own to carry to a laxer platform.
     */
    private static boolean isRuntimePathRejection(Exception failure) {
        return failure instanceof InvalidPathException;
    }
}
