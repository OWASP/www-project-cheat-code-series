# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

Two things live side by side:

1. **The OWASP project website** — Jekyll pages ([index.md](index.md), [info.md](info.md), [leaders.md](leaders.md), [404.html](404.html), [tab_example.md](tab_example.md)) rendered by the remote theme `owasp/www--site-theme@main`, plus [project.owasp.yaml](project.owasp.yaml) (OWASP Nest metadata, schema-validated in CI).
2. **The Java proof of concept** ([src/](src/), [pom.xml](pom.xml)) — a library of deliberately vulnerable and deliberately secure implementations of the same operation, each driven by the same attack payloads. Path Traversal is the only vulnerability class implemented so far; per the roadmap in [index.md](index.md), XXE, Command Injection, and SQL Injection are meant to follow, as are other languages.

The point of the PoC is *comparison*: a developer should be able to look at the test results and see which remediation actually blocks the payloads and how much legitimate functionality each one costs.

## Commands

```bash
mvn test                                          # all tests
mvn test -Dtest=SecurePathProcessor_FileAPI_GetNameTest   # one test class
mvn test -Dtest='Vulnerable*Test'                 # subset by pattern
mvn test -Dtest=Foo#AttackCase_DoubleDotTraversal # one test method
mvn exec:java -Dexec.mainClass=org.owasp.cheatcode.pathtraversal.Main   # console demo over secureStorage/ and pwnStorage/
bundle exec jekyll serve                          # site preview (Gemfile is gitignored; github-pages gem)
```

Java 11, JUnit 5, Mockito, OWASP ESAPI 2.6. There is no linter or formatter configured. VS Code launch configs for `Main` and the current file are in [.vscode/launch.json](.vscode/launch.json).

## Test failures are the deliverable, not a bug

Surefire is configured with `testFailureIgnore=true` ([pom.xml:83](pom.xml#L83)), so `mvn test` exits 0 even when assertions fail. **Never "fix" a failing test by loosening `BasePathProcessorTest`** — the failures are the report. As of the last run: 98 tests, 22 failures, in two meaningful groups.

- **Vulnerable processors fail the `AttackCase_*` tests.** That failure *is* the demonstration that the payload lands (`Attack succeeded! CONFIDENTIAL DATA disclosed!`). A vulnerable processor that passes everything means the harness stopped reproducing the vulnerability.
- **Most secure processors fail `EdgeLegitCase_RelativePath_ShouldReadSubfolderLegitFile`.** They block traversal but also reject the legitimate `SomeSubFolder/sublegit.txt` case — the usability cost of a filename-only defence. Only [SecurePathProcessor_RelativePath_Validation](src/main/java/org/owasp/cheatcode/pathtraversal/SecurePathProcessor_RelativePath_Validation.java) and [SecurePathProcessor_RelativeToBaseFolder_Validation](src/main/java/org/owasp/cheatcode/pathtraversal/SecurePathProcessor_RelativeToBaseFolder_Validation.java) currently pass all seven.

When changing an implementation, diff the before/after failure set rather than chasing a green run.

## Architecture of the PoC

[PathProcessor](src/main/java/org/owasp/cheatcode/pathtraversal/PathProcessor.java) is the whole harness. `readFile()` → `calculateTargetPath()` runs a fixed pipeline that every implementation plugs into via two abstract methods:

- `isValidFilePath(input, errors)` — false means "traversal detected".
- `getSanitizedFilePath(input)` — only reached when validation failed **and** the protected `canSanitize` flag is true. Implementations that reject rather than repair set `canSanitize = false` in their constructor, which turns a detected attack into `UnsupportedOperationException` instead of a second attempt.
- `joinPaths(base, input)` is `protected` so a vulnerable variant can override it to demonstrate unsafe concatenation (see [VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat](src/main/java/org/owasp/cheatcode/pathtraversal/VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat.java)).

Every outcome is recorded on [ReadFileResult](src/main/java/org/owasp/cheatcode/pathtraversal/ReadFileResult.java) — public mutable fields, deliberately: tests assert on `isPathTraversalAttackDetected`, `isPathSanitized`, `fileReadResult`, `fileReadException` rather than on thrown exceptions, so a processor can silently succeed at an attack and still be observable.

Class names are the documentation. The pattern is `{Vulnerable|Secure}PathProcessor_{Technique}_{Variant}` — keep it, since the comparison table in the README and the test output are read by name.

### Test harness

[BasePathProcessorTest](src/test/java/org/owasp/cheatcode/pathtraversal/BasePathProcessorTest.java) holds all seven test cases; each concrete test class is ~10 lines that only override `createProcessor(baseDir)` and `getProcessorName()`. **Adding a new implementation means adding one such subclass — never new test methods.** New attack payloads go in [PathTraversalTestPayloads](src/test/java/org/owasp/cheatcode/pathtraversal/PathTraversalTestPayloads.java) (constants only) with a matching `@Test` in the base class, so every implementation is scored against it at once.

`@TempDir` builds this layout per test, which is why single-level traversal is *not* enough to reach the secret and double-level is:

```
tempDir/SecureStorage/baseWorkingDirectory/legit.txt   <- baseDir passed to the processor
tempDir/SecureStorage/baseWorkingDirectory/SomeSubFolder/sublegit.txt
tempDir/pwnStorage/secret.txt                          <- "Attack succeeded! CONFIDENTIAL DATA disclosed!"
```

The committed [secureStorage/](secureStorage/) and [pwnStorage/](pwnStorage/) directories mirror this for `Main`, which resolves `secureStorage/baseDir` relative to the working directory — run it from the repo root.

ESAPI reads [src/main/resources/esapi/](src/main/resources/esapi/) (`ESAPI.properties`, `validation.properties`); `Main.initializeESAPI()` points the resource directory there explicitly. Changing `Validator.FileName` or `HttpUtilities.ApprovedUploadExtensions` changes the pass/fail verdict of the ESAPI-based processors.

`Main.createProcessors()` must list every processor that has a test class — keep the two in sync, since the README results table is generated from the test run and the console walkthrough is meant to match it.

Known wart: `SecurePathProcessor_ESAPI_FileNameValidation` calls `getValidFileName(..., null, false)`. ESAPI rejects a null extension list outright, so its sanitizer can never return — every non-trivial input ends as `ValidationException: Internal Error`. It passes the attack cases by failing closed, not by sanitizing.

## CI

[.github/workflows/validate-owasp-metadata.yaml](.github/workflows/validate-owasp-metadata.yaml) validates `*.owasp.yaml` against the OWASP Nest schema on push/PR touching that file. **The Java build and tests are not run in CI** — verify locally before pushing.
