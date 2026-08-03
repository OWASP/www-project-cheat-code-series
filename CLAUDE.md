# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

Two things live side by side:

1. **The OWASP project website** — Jekyll pages ([index.md](index.md), [info.md](info.md), [leaders.md](leaders.md), [404.html](404.html), [tab_example.md](tab_example.md)) rendered by the remote theme `owasp/www--site-theme@main`, plus [project.owasp.yaml](project.owasp.yaml) (OWASP Nest metadata, schema-validated in CI).
2. **The Java proof of concept** ([src/](src/), [pom.xml](pom.xml)) — a library of deliberately vulnerable and deliberately secure implementations of the same operation, each driven by the same attack payloads. Path Traversal is the only vulnerability class implemented so far; per the roadmap in [index.md](index.md), XXE, Command Injection, and SQL Injection are meant to follow, as are other languages.

The point of the PoC is *comparison*: a developer should be able to look at the test results and see which remediation actually blocks the payloads and how much legitimate functionality each one costs.

## Commands

```bash
mvn clean test                                    # all tests; green when reality matches the declared matrix
mvn test -Dtest=SecurePathProcessor_FileAPI_GetNameTest   # one test class
mvn test -Dtest='Vulnerable*Test'                 # subset by pattern
mvn test -Dtest=Foo#AttackCase_DoubleDotTraversal # one test method
mvn exec:java@report                              # build target/report/index.html + results-table.md
mvn exec:java -Dexec.mainClass=org.owasp.cheatcode.pathtraversal.Main   # console demo over secureStorage/ and pwnStorage/
bundle exec jekyll serve                          # site preview (Gemfile is gitignored; github-pages gem)
```

Java 11, JUnit 5, Mockito, OWASP ESAPI 2.6, Gson (test scope only). There is no linter or formatter configured. VS Code launch configs for `Main` and the current file are in [.vscode/launch.json](.vscode/launch.json).

## The matrix is the report; the suite guards it

This changed in August 2026 — see [.design_docs/test-outcome-matrix.md](.design_docs/test-outcome-matrix.md) for the full rationale, including what was rejected. Anything you remember about `testFailureIgnore` and "22 expected failures" is obsolete.

Each test class declares, per payload, what its implementation does. The suite compares that declaration against what actually happens. **`mvn test` is green — 98 tests, 0 failures — and a red test is a real signal**, one of:

- **`MISMATCH`** — an implementation moved. Either a change altered its behaviour, or the declaration was wrong.
- **`UNDECLARED`** — a cell nobody has recorded an expectation for. The failure message prints the observed outcome and the exact `.expect(...)` line to add.

Green does **not** mean "nothing is vulnerable". A vulnerable processor that discloses the secret is a *passing* test, because `SECRET_DISCLOSED` is what it was declared to do. The demonstration is carried by the recorded outcome and the generated report, not by a failing assertion.

> **Never edit an expectation to make a run green.** Change one only with the evidence — the matrix diff is the reviewable artifact. This replaces the old rule about not loosening `BasePathProcessorTest`.

### The outcome vocabulary

[Outcome](src/test/java/org/owasp/cheatcode/harness/Outcome.java) is deliberately richer than pass/fail, because pass/fail cannot distinguish a rejection from a silent rewrite. Two values matter most:

- **`UNDETECTED_MISS`** — the implementation did not detect the payload; the read failed only because `../` from the base directory lands one level short of `pwnStorage/`. A near miss, never a defence.
- **`REJECTED_BY_RUNTIME`** — the JDK refused the path (`InvalidPathException` on an embedded NUL), not the implementation. Seven of fourteen implementations score this on the null-byte payload; the old pass/fail table showed all fourteen as clean.

[Verdict](src/test/java/org/owasp/cheatcode/harness/Verdict.java) interprets an outcome given the payload's `PayloadKind` — the same outcome means opposite things for a legitimate input and an attack. Verdict colours the report; test pass/fail is orthogonal.

Classification lives entirely in [OutcomeClassifier](src/test/java/org/owasp/cheatcode/pathtraversal/OutcomeClassifier.java) — one function, so every cell is classified identically. Order matters there: disclosure is checked first.

## Architecture of the PoC

[PathProcessor](src/main/java/org/owasp/cheatcode/pathtraversal/PathProcessor.java) is the whole harness. `readFile()` → `calculateTargetPath()` runs a fixed pipeline that every implementation plugs into via two abstract methods:

- `isValidFilePath(input, errors)` — false means "traversal detected".
- `getSanitizedFilePath(input)` — only reached when validation failed **and** the protected `canSanitize` flag is true. Implementations that reject rather than repair set `canSanitize = false` in their constructor, which turns a detected attack into `UnsupportedOperationException` instead of a second attempt.
- `joinPaths(base, input)` is `protected` so a vulnerable variant can override it to demonstrate unsafe concatenation (see [VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat](src/main/java/org/owasp/cheatcode/pathtraversal/VulnerablePathProcessor_Default_NoChecks_ImproperPathConcat.java)).

Every outcome is recorded on [ReadFileResult](src/main/java/org/owasp/cheatcode/pathtraversal/ReadFileResult.java) — public mutable fields, deliberately: `isPathTraversalAttackDetected`, `isPathSanitized`, `fileReadResult` and `fileReadException` are observed rather than exceptions being caught, so a processor can silently succeed at an attack and still be visible. `OutcomeClassifier` reads all four to decide the cell's `Outcome`; tests assert on that, never on the raw fields.

Class names are the documentation. The pattern is `{Vulnerable|Secure}PathProcessor_{Technique}_{Variant}` — keep it, since the comparison table in the README and the test output are read by name.

### Test harness

`src/main` is the exhibit — only the implementations a developer is meant to read. The harness and report generator are **test scope**: [org/owasp/cheatcode/harness/](src/test/java/org/owasp/cheatcode/harness/) (generic: `Outcome`, `Verdict`, `Platform`, `Expectations`, `CellResult`, `ResultRecorder`) and [org/owasp/cheatcode/report/](src/test/java/org/owasp/cheatcode/report/). Keep it that way — do not add report machinery to `src/main`.

[BasePathProcessorTest](src/test/java/org/owasp/cheatcode/pathtraversal/BasePathProcessorTest.java) holds all seven test methods; each is a one-line call to `assertCell(Payload.X)`. A concrete test class overrides `createProcessor`, `getProcessorName`, `describe` and `expected` — and **never adds test methods**.

**Explicit `@Test` methods, not `@TestFactory` or `@ParameterizedTest`.** This is a deliberate rejection, not an oversight: stepping through one case in the VS Code debugger is the project's best learning tool, and dynamic tests debug badly. `assertCell` keeps `result`, `actual` and `expectation` as separate locals rather than chaining, so a single step-over shows each value in turn. Do not "tidy" that into a chain.

New payloads go in [Payload](src/test/java/org/owasp/cheatcode/pathtraversal/Payload.java) with a matching `@Test` in the base class. **Payload strings must be literals** — `LEGIT_SUBFOLDER_FILE` was previously built with `File.separator`, which silently made it a different payload per platform. Never reintroduce that.

Adding an implementation or a payload: run it first, read the `UNDECLARED` failures (which print the observed outcome and the line to add), check each observed outcome is actually correct, then declare it. An expectation written before the run is a guess.

[PathTraversalFixture](src/test/java/org/owasp/cheatcode/pathtraversal/PathTraversalFixture.java) builds this layout per test under `@TempDir`, which is why single-level traversal is *not* enough to reach the secret and double-level is:

```
tempDir/SecureStorage/baseWorkingDirectory/legit.txt   <- baseDir passed to the processor
tempDir/SecureStorage/baseWorkingDirectory/SomeSubFolder/sublegit.txt
tempDir/pwnStorage/secret.txt                          <- "Attack succeeded! CONFIDENTIAL DATA disclosed!"
```

The committed [secureStorage/](secureStorage/) and [pwnStorage/](pwnStorage/) directories mirror this for `Main`, which resolves `secureStorage/baseDir` relative to the working directory — run it from the repo root.

### Reporting and platforms

Each cell writes one JSON file to `target/cheatcode-results/<platform>/`. `mvn exec:java@report` reads every platform directory it finds and emits `target/report/index.html` (self-contained, no CDN) plus `results-table.md`, which is pasted into the README — so the published table cannot drift from what the code does. Regenerate and paste it whenever the matrix changes.

Only Windows results exist so far. Cells known to be platform-dependent (the `..\..\` payload) are declared with `on(WINDOWS, ...)` specifically, so a Linux run reports them as `UNDECLARED` rather than as regressions. Declaring an outcome for a platform nobody has run on is guessing — don't.

ESAPI reads [src/main/resources/esapi/](src/main/resources/esapi/) (`ESAPI.properties`, `validation.properties`); `Main.initializeESAPI()` points the resource directory there explicitly. Changing `Validator.FileName` or `HttpUtilities.ApprovedUploadExtensions` changes the pass/fail verdict of the ESAPI-based processors.

`Main.createProcessors()` must list every processor that has a test class — keep the two in sync, since the README results table is generated from the test run and the console walkthrough is meant to match it.

The two ESAPI filename processors reach identical verdicts by different routes, and the distinction is the point of having both: `SecurePathProcessor_ESAPI_FileNameValidation` takes its allowed extensions from `ESAPI.securityConfiguration().getAllowedFileExtensions()` (config-driven), while `SecurePathProcessor_ESAPI_DefaultFileNameValidation` hard-codes the list in Java. Note that `getValidFileName` rejects a null/empty extension list outright — passing `null` yields `ValidationException: Internal Error` and silently disables the sanitizer rather than allowing any extension.

## CI

[.github/workflows/validate-owasp-metadata.yaml](.github/workflows/validate-owasp-metadata.yaml) validates `*.owasp.yaml` against the OWASP Nest schema on push/PR touching that file.

[.github/workflows/java-outcome-matrix.yaml](.github/workflows/java-outcome-matrix.yaml) runs the suite across `{windows, ubuntu, macos} × JDK {11, 21}` and publishes the merged report as the `outcome-matrix-report` artifact.

**Only `windows-latest` + JDK 21 is a gate**; every other combination is `continue-on-error`. That is not laziness — those combinations have no declared expectations, so red there means `UNDECLARED` ("nobody has recorded what this does") rather than a regression. Linux and macOS will report the `..\..\` cells as undeclared *by design*. Promote a combination to required by removing it from the `continue-on-error` expression once its cells are declared, using that job's uploaded results as the evidence.

JDK 11 is the declared floor (README, `maven.compiler.source`) but the expectations were recorded on 21 and 25, verified identical on both. Nobody has observed JDK 11. If that job goes red, check the "Java 11+" claim before touching the matrix.
