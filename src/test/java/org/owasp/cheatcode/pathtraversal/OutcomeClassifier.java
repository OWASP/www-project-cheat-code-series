package org.owasp.cheatcode.pathtraversal;

import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

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

        if (isRuntimePathRejection(failure)) {
            // The JDK refused the path before the implementation's logic mattered.
            return Outcome.REJECTED_BY_RUNTIME;
        }

        if (result.resolvedPath == null) {
            // It threw before it ever named a file, so it refused the input - whether by
            // rejecting it outright or by a repair attempt that threw instead of returning a
            // repaired name. Either way the caller got an exception rather than the contents of
            // some other file, which is the only difference a caller can actually observe.
            return Outcome.REJECTED;
        }

        if (failure instanceof NoSuchFileException) {
            // It named a file and the file was not there. *Which* file it named is the whole
            // story: a rewritten path means the implementation acted, an untouched one means
            // the fixture layout is the only reason the read failed.
            return Boolean.TRUE.equals(inputRewritten(result))
                    ? Outcome.SANITIZED_MISS
                    : Outcome.UNDETECTED_MISS;
        }

        // It named a file, and something other than "not found" went wrong. Always worth a look.
        return Outcome.UNEXPECTED_ERROR;
    }

    private static Outcome classifySuccessfulRead(Payload payload, ReadFileResult result) {
        if (PathTraversalFixture.SECRET_FILE_CONTENT.equals(result.fileReadResult)) {
            return Outcome.SECRET_DISCLOSED;
        }

        boolean servedWhatWasAskedFor = result.fileReadResult.equals(payload.expectedContent());
        if (!servedWhatWasAskedFor) {
            return Outcome.READ_UNEXPECTED;
        }
        return Boolean.TRUE.equals(inputRewritten(result))
                ? Outcome.SANITIZED_HIT
                : Outcome.READ_OK;
    }

    /**
     * Did the implementation read from somewhere other than the naive join of the base directory
     * and the raw input - that is, did it change the input on the way through?
     *
     * <p>This replaces the old {@code isPathSanitized} flag, which the base class used to set on
     * the implementation's behalf. Derived rather than declared, so an implementation can neither
     * claim a rewrite it did not perform nor hide one it did. It also asks a slightly different
     * question than the flag did: the flag recorded which branch ran, this records what actually
     * changed, so a repair that happens to be a no-op no longer counts as one.
     *
     * <p>Package-private so that the recorded evidence uses the same definition the
     * classification does, rather than a second copy of it.
     *
     * @return null when the implementation never resolved a path, so the question does not apply
     */
    static Boolean inputRewritten(ReadFileResult result) {
        if (result == null || result.resolvedPath == null) {
            return null;
        }

        Path naive;
        try {
            naive = Paths.get(result.baseDirectory, result.userProvidedPath);
        } catch (InvalidPathException e) {
            // Paths.get cannot even express the raw input - an embedded NUL, in practice. If the
            // implementation resolved something anyway, it must have changed the input to get
            // there. (An implementation that did not is unreachable here: it would have thrown
            // InvalidPathException itself and been classified REJECTED_BY_RUNTIME above.)
            return Boolean.TRUE;
        }

        return !naive.equals(result.resolvedPath);
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
