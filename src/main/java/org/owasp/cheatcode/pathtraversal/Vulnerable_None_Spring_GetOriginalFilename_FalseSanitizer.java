package org.owasp.cheatcode.pathtraversal;

import java.nio.file.Paths;

import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

/**
 * This class contains a vulnerable path processing implementation
 * that uses MultipartFile.getOriginalFilename() for path processing.
 * This is vulnerable because getOriginalFilename() returns the original filename
 * from the client without any sanitization, making it susceptible to path traversal attacks.
 */
public class VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName extends PathProcessor {

    public VulnerablePathProcessor_ImproperAPIUse_MultipartFileGetOriginalName(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public String getResource(String userInput) throws Exception {
        // A real upload handler takes the name from the multipart part; this mock stands in for
        // one, preserving the client's string exactly as a browser would send it.
        MultipartFile upload =
                new MockMultipartFile("file", userInput, "text/plain", "fake content".getBytes());

        // Vulnerable: getOriginalFilename() returns the *client's* string, path separators and
        // all. It sits where a sanitizer would sit and reads like one, which is the whole trap -
        // the API name suggests the framework has handled this, and it has not.
        // https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/multipart/MultipartFile.html#getOriginalFilename()
        String fileName = upload.getOriginalFilename();

        return readFrom(Paths.get(baseDirectory, fileName));
    }
}
