package org.owasp.cheatcode.pathtraversal;

import java.io.File;

/**
 * Contains constants for legitimate path test payloads used in security testing.
 */
public final class LegitimatePathsTestPayloads {
    private LegitimatePathsTestPayloads() {
        // Prevent instantiation
    }

    // Simple legitimate file name
    public static final String SIMPLE_FILE = "legit.txt";
    
    // Legitimate file in subfolder
    public static final String SUBFOLDER_FILE = "SomeSubFolder" + File.separator + "sublegit.txt";
} 