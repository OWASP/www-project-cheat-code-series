package org.owasp.cheatcode.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.esapi.errors.ValidationException;

@DisplayName("Path Processor Tests")
abstract class BasePathProcessorTest {
    
    protected PathProcessor processor;
    private static final String PURPLE = "\u001B[35m";
    private static final String RESET = "\u001B[0m";
    protected static final String PUBLIC_FILE_CONTENT = "Test file content";
    protected static final String SUBFOLDER_CONTENT = "Subfolder file content";
    protected static final String SECRET_FILE_CONTENT = "Attack succeeded! CONFIDENTIAL DATA disclosed!";
    @TempDir
    protected Path tempDir;
    
    abstract PathProcessor createProcessor(String baseDir);
    abstract String getProcessorName();
    
    @BeforeEach
    void setUp() throws IOException {
        // Create SecureStorage directory structure
        Path secureStorage = tempDir.resolve("SecureStorage");
        Files.createDirectories(secureStorage);
        
        // Create base directory inside SecureStorage
        Path baseDir = secureStorage.resolve("baseWorkingDirectory");
        Files.createDirectories(baseDir);
        
        // Initialize processor with the base directory
        processor = createProcessor(baseDir.toString());
        System.out.println("\nTesting " + processor.getClass().getSimpleName() + ":");
        
        // Create a legitimate test file in baseDir
        Path legitFile = baseDir.resolve("legit.txt");
        Files.writeString(legitFile, PUBLIC_FILE_CONTENT);
        
        // Create a subfolder with a file in baseDir
        Path subfolder = baseDir.resolve("SomeSubFolder");
        Files.createDirectories(subfolder);
        Path subfolderFile = subfolder.resolve("sublegit.txt");
        Files.writeString(subfolderFile, SUBFOLDER_CONTENT);
        
        // Create a "sensitive" file in a parent directory
        Path sensitiveDir = tempDir.resolve("pwnStorage");
        Files.createDirectories(sensitiveDir);
        Path sensitiveFile = sensitiveDir.resolve("secret.txt");
        Files.writeString(sensitiveFile, SECRET_FILE_CONTENT);
    }

    @Test
    void LegitCase_NormalFileName_ShouldReadFile() throws IOException {
        ReadFileResult result = processor.readFile(LegitimatePathsTestPayloads.SIMPLE_FILE);
        assertFalse(result.isPathTraversalAttackDetected);
        assertFalse(result.isPathSanitized);
        assertEquals(PUBLIC_FILE_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }
    
    @Test
    void EdgeLegitCase_RelativePath_ShouldReadSubfolderLegitFile() throws IOException {
        ReadFileResult result = processor.readFile(LegitimatePathsTestPayloads.SUBFOLDER_FILE);
        assertFalse(result.isPathTraversalAttackDetected);
        assertFalse(result.isPathSanitized);
        assertEquals(SUBFOLDER_CONTENT, result.fileReadResult);
        assertNull(result.fileReadException);
    }

    @Test
    void AttackCase_SingleLevelTraversal() {
        ReadFileResult result = processor.readFile(PathTraversalTestPayloads.SINGLE_LEVEL_TRAVERSAL);
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.isPathTraversalAttackDetected, "Attack was not detected");
        assertNotNull(result.fileReadException);        
        assertTrue(isOneOfExpectedExceptions(result.fileReadException),
                  "Got unexpected exception: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void AttackCase_DoubleLevelTraversal() {
        ReadFileResult result = processor.readFile(PathTraversalTestPayloads.DOUBLE_LEVEL_TRAVERSAL);
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.isPathTraversalAttackDetected, "Attack was not detected");
        assertNotNull(result.fileReadException);        
        assertTrue(isOneOfExpectedExceptions(result.fileReadException), 
                  "Got unexpected exception: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void AttackCase_DoubleDotTraversal() {
        ReadFileResult result = processor.readFile(PathTraversalTestPayloads.DOUBLE_DOT_TRAVERSAL);
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.isPathTraversalAttackDetected, "Attack was not detected");        
        assertNotNull(result.fileReadException);
        assertTrue(isOneOfExpectedExceptions(result.fileReadException),
                  "Got unexpected exception: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void AttackCase_WindowsStylePathTraversal() {   
        ReadFileResult result = processor.readFile(PathTraversalTestPayloads.WINDOWS_STYLE_TRAVERSAL);
        assertNull(result.fileReadResult, PURPLE + "Attack succeeded! Secret file was read! Content: " + result.fileReadResult + RESET);
        assertTrue(result.isPathTraversalAttackDetected, "Attack was not detected");
        assertNotNull(result.fileReadException);
            assertTrue(isOneOfExpectedExceptions(result.fileReadException),
                  "Got unexpected exception: " + 
                  (result.fileReadException != null ? result.fileReadException.getClass().getSimpleName() : "null"));
    }
    
    @Test
    void MalformedCase_NullCharacterInput() {
        ReadFileResult result = processor.readFile(PathTraversalTestPayloads.NULL_CHARACTER_INJECTION);       
        
        if (result.isPathSanitized) {
            // If path was sanitized, it should have removed the null character
            assertTrue(result.fileReadResult != null && !result.sanitizedFilePathToReadFrom.toString().contains("\0"));
        } else {
            // If not sanitized, it should throw
            assertNotNull(result.fileReadException);
        }
    }

    private boolean isOneOfExpectedExceptions(Exception e) {
        return e instanceof UnsupportedOperationException || 
               e instanceof NoSuchFileException ||
               e instanceof org.owasp.esapi.errors.ValidationException ||
               (e.getCause() != null && e.getCause() instanceof ValidationException);
    }
} 