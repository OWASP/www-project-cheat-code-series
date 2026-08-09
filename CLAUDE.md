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
mvn test -Dtest=Secure_RawString_JavaFileAPI_GetName_SanitizerTest   # one test class
mvn test -Dtest='Vulnerable*Test'                 # subset by pattern
mvn test -Dtest=Foo#AttackCase_DoubleDotTraversal # one test method
mvn exec:java@report                              # build target/report/index.html + results-table.md
mvn exec:java -Dexec.mainClass=org.owasp.cheatcode.pathtraversal.Main   # console demo over secureStorage/ and pwnStorage/
bundle exec jekyll serve                          # site preview (Gemfile is gitignored; github-pages gem)
```

Java 17, JUnit 5, Mockito, Spring 7.0.8, OWASP ESAPI 2.7, Gson (test scope only). The Java floor was 11 until August 2026; Spring 7 raised it, and Spring is the only reason for it. Dependency versions are pinned with reasons — read [.design_docs/dependency-triage.md](.design_docs/dependency-triage.md) before changing one, and note that `commons-configuration` is excluded from ESAPI on purpose. There is no linter or formatter configured. VS Code launch configs for `Main` and the current file are in [.vscode/launch.json](.vscode/launch.json).

## The matrix is the report; the suite guards it

This changed in August 2026 — see [.design_docs/test-outcome-matrix.md](.design_docs/test-outcome-matrix.md) for the full rationale, including what was rejected. Anything you remember about `testFailureIgnore` and "22 expected failures" is obsolete.

Each test class declares, per payload, what its implementation does. The suite compares that declaration against what actually happens. **`mvn test` is green — 105 tests, 0 failures — and a red test is a real signal**, one of:

- **`MISMATCH`** — an implementation moved. Either a change altered its behaviour, or the declaration was wrong.
- **`UNDECLARED`** — a cell nobody has recorded an expectation for. The failure message prints the observed outcome and the exact `.expect(...)` line to add.
- **`DISCIPLINE VIOLATION`** — the implementation contradicted the discipline its own class name claims: a `_Validator` that rewrote the input, or a `_Sanitizer` that threw. Checked by `Discipline.violatedBy`, asserted ahead of the outcome comparison because it names the cause rather than the symptom. Fix the code or the name — never rename a class just to silence it.

Green does **not** mean "nothing is vulnerable". A vulnerable processor that discloses the secret is a *passing* test, because `SECRET_DISCLOSED` is what it was declared to do. The demonstration is carried by the recorded outcome and the generated report, not by a failing assertion.

> **Never edit an expectation to make a run green.** Change one only with the evidence — the matrix diff is the reviewable artifact. This replaces the old rule about not loosening `BasePathProcessorTest`.

### The outcome vocabulary

[Outcome](src/test/java/org/owasp/cheatcode/harness/Outcome.java) has nine values and is deliberately richer than pass/fail, because pass/fail cannot distinguish a rejection from a silent rewrite. Two values matter most:

- **`UNDETECTED_MISS`** — the implementation read from exactly the path the raw input names, changing nothing; the read failed only because `../` from the base directory lands one level short of `pwnStorage/`. A near miss, never a defence.
- **`REJECTED_BY_RUNTIME`** — the JDK refused the path (`InvalidPathException` on an embedded NUL), not the implementation. Eight of fifteen implementations score this on the null-byte payload; the old pass/fail table showed all fifteen as clean.

`SANITIZE_FAILED` was merged into `REJECTED` in August 2026: without a separate sanitize phase, "refused outright" and "the repair attempt threw" are the same event from where the caller stands — no file named, an exception returned. Which route was taken is still visible in `evidence.exceptionClass` and in the implementation's own code.

**"Rewrote the input" is derived, not declared.** `SANITIZED_MISS` vs `UNDETECTED_MISS` and `SANITIZED_HIT` vs `READ_OK` turn on whether the implementation resolved a different path than `Paths.get(base, rawInput)` — see `OutcomeClassifier.inputRewritten`. The old `isPathSanitized` / `isPathTraversalAttackDetected` flags are gone, so an implementation can neither claim a rewrite it did not perform nor hide one it did.

[Verdict](src/test/java/org/owasp/cheatcode/harness/Verdict.java) interprets an outcome given the payload's `PayloadKind` — the same outcome means opposite things for a legitimate input and an attack. Verdict colours the report; test pass/fail is orthogonal.

Classification lives entirely in [OutcomeClassifier](src/test/java/org/owasp/cheatcode/pathtraversal/OutcomeClassifier.java) — one function, so every cell is classified identically. Order matters there: disclosure is checked first.

## Architecture of the PoC

**One implementation, one method.** Each processor implements a single `getResource(String userInput)` that validates, repairs or refuses and then reads — the shape the equivalent function has in a real application. Restructured in August 2026; anything you remember about `isValidFilePath`, `getSanitizedFilePath`, `canSanitize` or `joinPaths` is obsolete. The point is that a developer can read one file top to bottom without reassembling the flow from a base class, so **keep the whole technique in that one method** — do not factor a check back out into a helper the reader has to chase.

[PathProcessor](src/main/java/org/owasp/cheatcode/pathtraversal/PathProcessor.java) contains no defence of its own. It supplies exactly two things:

- `readFrom(Path)` — the only sanctioned route to content. It reads and records the resolved path. Calling `Files.readString` directly leaves the report blind and breaks the rewrite derivation.
- `readFile(String)` — `final`, harness-facing. Runs `getResource`, guards null/empty input, and *reports* the result rather than throwing, so a processor that silently succeeds at an attack stays visible.

### Validation is the recommendation; sanitization is the fallback

The project's design position, and it should be visible in every header, every `describe()` and the report. **Production code should validate and refuse. Sanitizing is what you do when something outside your control forces you to accept input you cannot reject.**

The security argument is the familiar one — repair-by-deletion can assemble the payload it removes, which is why `Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer` discloses the secret on `....//`. The argument that generalises further is about *predictability*: a sanitizer silently changes which file gets read. The caller asks for `SomeSubFolder/sublegit.txt` and the application serves `SomeSubFoldersublegit.txt`, or nothing, and raises no error anywhere. Nobody is told the request was not honoured. A validator loses exactly the same functionality and says so.

[Secure_RawString_Regex_AllowAlphaNumericDot_Validator](src/main/java/org/owasp/cheatcode/pathtraversal/Secure_RawString_Regex_AllowAlphaNumericDot_Validator.java) is the reference implementation — an allow-list, refusing. It was a sanitizer until August 2026; the conversion is what the position looks like applied. Two cells moved and both are informative: `SomeSubFolder/` went `SANITIZED_MISS` → `REJECTED` (same loss, now audible), and the null byte went `SANITIZED_HIT` → `REJECTED`, meaning the defence is now the implementation's rather than the JDK's and survives a platform with laxer path parsing.

When adding a `Sanitizer`, name the constraint that makes repair the only option. If none can be named, the class is a counter-example, not a recommendation, and its header must say so.

**Each implementation commits to one discipline, and its name says which.** A `Validator` refuses by throwing and never rewrites. A `Sanitizer` rewrites unconditionally and never refuses. A `NoDefence` does neither. Do not write the hybrid shape — `if (looksBad(input)) { input = repair(input); }` — unless the class exists to exhibit it: four classes carried that guard until August 2026 and in every one it was provably dead, because a repair is a no-op exactly when its own check says the input is clean. The guard bought nothing and implied a validation phase that was not there.

The distinction is the matrix's central lesson, and there is a matched pair to prove it: [Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator](src/main/java/org/owasp/cheatcode/pathtraversal/Vulnerable_RawString_StringOps_ContainsDotDotSlash_Validator.java) and [its Sanitizer twin](src/main/java/org/owasp/cheatcode/pathtraversal/Vulnerable_RawString_StringOps_ContainsDotDotSlash_Sanitizer.java) apply the identical rule — "this input involves `../`" — and differ on exactly one cell of seven. On `....//....//pwnStorage//secret.txt` the validator scores `REJECTED` and the sanitizer scores `SECRET_DISCLOSED`, because deleting `../` splices a fresh one out of what surrounded it. Both remain `Vulnerable` on their own merit, since `..\..\` defeats each. Keep them adjacent in `Main.createProcessors()` and in the report.

Refusing means throwing. Repairing means changing the string and reading the result — in plain code, with no framework flag. The secure rewriters' cost to `SomeSubFolder/` is the same lesson seen from the other side.

Every outcome is recorded on [ReadFileResult](src/main/java/org/owasp/cheatcode/pathtraversal/ReadFileResult.java) — public mutable fields, deliberately: `baseDirectory`, `userProvidedPath`, `resolvedPath`, `fileReadResult` and `fileReadException` are observed rather than exceptions being caught. `OutcomeClassifier` reads them to decide the cell's `Outcome`; tests assert on that, never on the raw fields.

Class names are the documentation. The pattern is **`{Verdict}_{Strategy}_{Library}_{Variant}_{Discipline}`** — keep it, since the comparison table in the README and the test output are read by name. Adopted August 2026; anything you remember about `{Vulnerable|Secure}PathProcessor_{Technique}_{Variant}` is obsolete, and the `PathProcessor` infix is gone because the package already says it. See [.design_docs/naming-scheme-decision.md](.design_docs/naming-scheme-decision.md) for the full rationale, including why underscores deviate from Java convention on purpose.

| Slot | Question | Vocabulary |
|---|---|---|
| Verdict | May I use this? | `Secure`, `Vulnerable` |
| Strategy | What does the code decide on? | `RawString`, `LexicalPath`, `ResolvedPath`, `Indirection`, `None` |
| Library | What do I call? | `JavaNIO`, `JavaFileAPI`, `Regex`, `StringOps`, `ESAPI`, `Spring` |
| Variant | Which flavour of that call? | free text |
| Discipline | What does it do once it holds the input? | `Validator`, `Sanitizer`, `NoDefence`, `FalseSanitizer` |

Rules that are easy to get wrong:

- **A library is never a strategy.** ESAPI file-name validation is a whitelist regex over the string → `RawString`. `File.getName()` does no resolution → `RawString`; it is secure because it *discards* the directory portion, not because it resolves anything.
- **`ConditionallySecure` is deliberately not in the Verdict vocabulary yet.** Naming a class that asserts a symlink, TOCTOU or config precondition no payload exercises — the same guessing forbidden for undeclared platforms. Candidates and the promotion cost are in [ToDo.md](ToDo.md).
- **`FalseSanitizer`** is for code that occupies a sanitizer's position and provides nothing — [Vulnerable_None_Spring_GetOriginalFilename_FalseSanitizer](src/main/java/org/owasp/cheatcode/pathtraversal/Vulnerable_None_Spring_GetOriginalFilename_FalseSanitizer.java), whose `getOriginalFilename()` reads like a framework sanitizer and returns the client's string verbatim. It is matrix-identical to `Vulnerable_None_JavaNIO_PathsGet_NoDefence` on all seven payloads, so the name is the *only* place that distinction can live — which is exactly why the trap belongs in a fixed-vocabulary slot rather than in free-text `Variant`.
- Verdict is `Vulnerable`, never `Insecure`. Acronyms keep conventional casing: `ESAPI`, not `Esapi`.

### Test harness

`src/main` is the exhibit — only the implementations a developer is meant to read. The harness and report generator are **test scope**: [org/owasp/cheatcode/harness/](src/test/java/org/owasp/cheatcode/harness/) (generic: `Outcome`, `Verdict`, `Platform`, `Expectations`, `CellResult`, `ResultRecorder`) and [org/owasp/cheatcode/report/](src/test/java/org/owasp/cheatcode/report/). Keep it that way — do not add report machinery to `src/main`.

[BasePathProcessorTest](src/test/java/org/owasp/cheatcode/pathtraversal/BasePathProcessorTest.java) defines all seven test methods; each is a one-line call to `assertCell(Payload.X)`. A concrete test class overrides `createProcessor`, `getProcessorName`, `describe` and `expected`, and **declares nothing else of its own** — no new payloads, no assertions.

**Every concrete class re-declares the seven methods as `@Test @Override` stubs that call `super`.** They are in a folded `// #region` at the end of each file and add nothing to the run — deleting the block changes neither the test count nor an assertion. They exist because the VS Code Test Explorer discovers only methods a class *declares*, never one it inherits, so without them "Debug Test" on a single case launches all seven. Changed 2026-08-09; see [.design_docs/test_run_options.md](.design_docs/test_run_options.md) for the evidence, including why the old inherited-only shape never allowed debugging one case.

**Explicit `@Test` methods, not `@TestFactory` or `@ParameterizedTest`.** This is a deliberate rejection, not an oversight: stepping through one case in the VS Code debugger is the project's best learning tool, and dynamic tests debug badly. `assertCell` keeps `result`, `actual` and `expectation` as separate locals rather than chaining, so a single step-over shows each value in turn. Do not "tidy" that into a chain.

New payloads go in [Payload](src/test/java/org/owasp/cheatcode/pathtraversal/Payload.java) with a matching `@Test` in the base class **and a stub in all fifteen concrete classes** — the step that is easiest to forget. Forgetting it is not a silent test loss: the inherited method still runs, it just stops being individually debuggable. **Payload strings must be literals** — `LEGIT_SUBFOLDER_FILE` was previously built with `File.separator`, which silently made it a different payload per platform. Never reintroduce that.

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

The two ESAPI filename processors reach identical verdicts by different routes, and the distinction is the point of having both: `Secure_RawString_ESAPI_FileNameFromConfig_Validator` takes its allowed extensions from `ESAPI.securityConfiguration().getAllowedFileExtensions()` (config-driven), while `Secure_RawString_ESAPI_FileNameHardCodedExtensions_Validator` hard-codes the list in Java. Note that `getValidFileName` rejects a null/empty extension list outright — passing `null` yields `ValidationException: Internal Error` and silently disables the sanitizer rather than allowing any extension.

## CI

[.github/workflows/validate-owasp-metadata.yaml](.github/workflows/validate-owasp-metadata.yaml) validates `*.owasp.yaml` against the OWASP Nest schema on push/PR touching that file.

[.github/workflows/java-outcome-matrix.yaml](.github/workflows/java-outcome-matrix.yaml) runs the suite across `{windows, ubuntu, macos} × JDK {11, 21}` and publishes the merged report as the `outcome-matrix-report` artifact.

**Only `windows-latest` + JDK 21 is a gate**; every other combination is `continue-on-error`. That is not laziness — those combinations have no declared expectations, so red there means `UNDECLARED` ("nobody has recorded what this does") rather than a regression. Linux and macOS will report the `..\..\` cells as undeclared *by design*. Promote a combination to required by removing it from the `continue-on-error` expression once its cells are declared, using that job's uploaded results as the evidence.

JDK 17 is the declared floor (README, `maven.compiler.source`) but the expectations were recorded on 21 and 25, verified identical on both. Nobody has observed JDK 17. If that job goes red, check the "Java 17+" claim before touching the matrix.
