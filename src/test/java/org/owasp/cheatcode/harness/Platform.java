package org.owasp.cheatcode.harness;

import java.util.Locale;

/**
 * The operating system family a run was recorded on.
 *
 * <p>Path traversal behaviour is not portable — {@code \} is a separator on Windows and an
 * ordinary filename character on POSIX, and macOS filesystems are case-insensitive by default —
 * so an outcome is only meaningful alongside the platform that produced it.
 */
public enum Platform {

    WINDOWS,
    LINUX,
    MACOS,

    /** Anything the harness does not recognise. Expectations can never be declared against it. */
    OTHER;

    /**
     * @return the platform this JVM is running on
     */
    public static Platform current() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return WINDOWS;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return MACOS;
        }
        if (os.contains("nux") || os.contains("nix") || os.contains("aix")) {
            return LINUX;
        }
        return OTHER;
    }
}
