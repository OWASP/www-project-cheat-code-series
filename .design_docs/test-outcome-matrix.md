# Test outcome matrix — replacing "red is the report"

**Repo:** https://github.com/OWASP/www-project-cheat-code-series

## Status — 2026-08-01

Steps 1–3 are **implemented**. Containers (step 5) are deliberately **deferred**,
and symlink payloads (step 4) are the first thing that will need them.

| Step | Status |
|---|---|
| 1. `Payload` / `Outcome` / classifier / `Platform` / JSON emission | Done |
| 2. Declared expectations, green suite, drop `testFailureIgnore` | Done |
| 3. `ReportGenerator` — HTML + README markdown from one source | Done |
| 4. Symlink and filesystem-dependent payloads | Deferred |
| 5. Containerised Linux variants, GH Actions OS matrix | Deferred |

**Result of the migration.** 98 tests, 0 failures, 98/98 cells `MATCH`. The old
suite reported 22 failures; the matrix reports 8 breaches, 13 near misses and 8
functionality losses — 29 cells that are not cleanly safe, i.e. **more** than the
old red count surfaced. The seven extra are `REJECTED_BY_RUNTIME` on the
null-byte payload, which the old suite scored as clean passes for all fourteen
implementations because the assertion only asked whether *something* threw.

Two things were found while migrating rather than designed in advance:

- `LegitimatePathsTestPayloads.SUBFOLDER_FILE` was built with `File.separator`
  (§5) — a live platform bug in the old harness.
- `Secure_PathProcessor_ESAPI_CombinedDirectoryAndFileNameValidation` is the one
  implementation whose design anticipates nested paths, and it still cannot serve
  `SomeSubFolder/sublegit.txt`. Worth a follow-up on its own.

### Deviations from the plan as written

- **`@TestFactory` was dropped.** §3 originally proposed generating the 98 cells
  as dynamic tests. Rejected on debuggability: stepping through a single case in
  the IDE is this project's best learning tool, and dynamic tests debug badly.
  Seven explicit one-line `@Test` methods instead — which also costs nothing
  against the documented contribution workflow, since it already required a
  payload constant plus a `@Test`.
- **Expectations default to platform-agnostic**, with `on(WINDOWS, …)` used only
  where behaviour is known to be platform-dependent. The stricter alternative —
  scoping every cell to the platform it was observed on — would make a first
  Linux run 98 `UNDECLARED`, which is honest but useless. Scoping only the
  backslash payload keeps the signal.

---

## 1. The problem

The suite has two jobs and can only do one.

- **As a report** it works: a failing `AttackCase_*` on a vulnerable
  implementation *is* the demonstration that the payload landed.
- **As a development tool** it is useless: with 22 expected failures out of 98,
  a change that breaks a secure implementation is indistinguishable from the
  background noise. There is no way to run the suite and ask "did I break
  anything?"

The instinct is a `demo-mode` / `dev-mode` feature flag with an `isVulnerable`
flag per implementation. **Rejected** — see §7.

The actual gap is that **the expected outcome of each (implementation × payload)
cell exists only in the README table and in the maintainer's head.** Nothing
executable knows that `Bypassable_StringContainsCheck` is *supposed* to survive
`../` and *supposed* to fall to `....//`.

14 implementations × 7 payloads = 98 cells, exactly 1:1 with the 98 tests. The
expectation is per-cell. Write it down and one always-green run serves both jobs.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Expectation granularity | **Per cell** (impl × payload × platform) | A class-level boolean cannot express partial defences or platform-dependent behaviour. See §7. |
| Where expectations live | **In the test subclass** | Type-safe, survives renames, keeps the one-small-file-per-implementation contribution story. The central view is generated, not authored. |
| Test style | **Seven explicit `@Test` methods**, one per payload | Debuggability is the product. See §3. |
| Outcome vocabulary | **Ten-value `Outcome` enum**, not pass/fail | ✅/❌ cannot distinguish "blocked" from "silently mangled into a nonexistent filename". See §4. |
| Report source of truth | **One JSON file per cell** under `target/cheatcode-results/<platform>/` | Survives a cross-platform merge; readable by any tooling. |
| Harness location | **Test scope only** (`org.owasp.cheatcode.harness`, `…report`) | `src/main` is the exhibit. Developers read it. Keep report machinery out of it. |
| Serialisation | **Gson**, test scope | One small dependency, no transitives. Hand-rolled JSON writing is easy; hand-rolled parsing is not. |
| Undeclared platform | **Fails the test** | Otherwise the matrix silently claims coverage it does not have — the same failure mode as today, inverted. |

## 3. Explicit `@Test` methods, not `@TestFactory`

`@TestFactory` or `@ParameterizedTest` would collapse the seven methods into one
and make "never add test methods" true by construction. **Rejected.**

Stepping through a single case in the VS Code debugger — breakpoint in the
processor, watch the payload string become a `Path`, watch the validator return
`false` — is the single best learning tool this project has. Dynamic tests
debug poorly: the tree is only populated after a run, and a breakpoint inside a
`@ParameterizedTest` stops on every invocation, so you step through seven cases
to inspect one.

So `BasePathProcessorTest` keeps seven named methods, each a one-liner:

```java
@Test
void AttackCase_DoubleDotTraversal() {
    assertCell(Payload.ATTACK_DOUBLE_DOT_TRAVERSAL);
}
```

`assertCell` deliberately keeps `result`, `actual` and `expectation` as separate
locals rather than chaining, so a single step-over shows each value in turn.

This costs nothing against today's workflow: the README already instructs
contributors to add a payload constant *and* a matching `@Test` in the base
class. Same two edits.

## 4. The outcome vocabulary

Traced against the real implementations, not guessed.
`SecurePathProcessor_StringContains_Simple` does not set `canSanitize = false`,
so `SomeSubFolder/sublegit.txt` is detected, repaired to
`SomeSubFoldersublegit.txt`, and fails with `NoSuchFileException`. That is not
"blocked" — it is *silently mangled into a filename that does not exist*, a
materially different usability story from a flat rejection. ✅/❌ cannot say so.

```java
enum Outcome {
    READ_OK,             // read succeeded with the payload's expected content
    SECRET_DISCLOSED,    // the payload reached the secret — the attack won
    READ_UNEXPECTED,     // a read succeeded but returned neither expected nor secret content
    REJECTED,            // detected; implementation refuses to repair (canSanitize = false)
    SANITIZE_FAILED,     // detected; the repair attempt itself threw
    SANITIZED_MISS,      // detected and repaired; the repaired target does not exist
    SANITIZED_HIT,       // detected and repaired; the read succeeded and the content is safe
    UNDETECTED_MISS,     // NOT detected; the read failed anyway — a near miss, not a defence
    REJECTED_BY_RUNTIME, // the JDK or filesystem refused the path, not the implementation
    UNEXPECTED_ERROR     // anything else — always worth looking at
}
```

Two of these earn their place immediately:

**`UNDETECTED_MISS`** is README footnote ¹ promoted from prose to data.
`Default_NoChecks` + `../pwnStorage/secret.txt` resolves to
`…/SecureStorage/pwnStorage/secret.txt`, which does not exist in the fixture.
The payload was *missed*, not *stopped*, and as a footnote under a ❌ it invites
the reader to conclude the implementation defended itself.

**`REJECTED_BY_RUNTIME`** separates "the implementation caught it" from "the
platform caught it". `Paths.get()` throws `InvalidPathException` on an embedded
NUL on every modern JVM, so most implementations "pass" the null-byte payload
today without containing a single line of code that looks at it. That is a
portability landmine — the same code on a platform with laxer path parsing has
no defence — and the current suite scores it as a clean pass for everyone.

### Verdict — the second axis

`Outcome` says what happened; `Verdict` says what it means, and depends on
whether the payload was supposed to work:

| Payload kind | Outcome | Verdict |
|---|---|---|
| `LEGITIMATE` | `READ_OK` | `SAFE` |
| `LEGITIMATE` | anything else | `FUNCTIONALITY_LOST` |
| `ATTACK` / `MALFORMED` | `SECRET_DISCLOSED` | `BREACH` |
| `ATTACK` / `MALFORMED` | `REJECTED`, `SANITIZE_FAILED`, `SANITIZED_MISS`, `SANITIZED_HIT` | `SAFE` |
| `ATTACK` / `MALFORMED` | `UNDETECTED_MISS`, `REJECTED_BY_RUNTIME` | `NEAR_MISS` |
| `ATTACK` / `MALFORMED` | `READ_UNEXPECTED`, `UNEXPECTED_ERROR` | `ERROR` |

`Verdict` colours the matrix. Test pass/fail (does the outcome match what was
declared?) is a separate, orthogonal thing — a cell can be `BREACH` and green,
which is precisely the point.

## 5. Payloads as data, with literal strings

`LegitimatePathsTestPayloads.SUBFOLDER_FILE` is currently built with
`File.separator`, so the payload is `SomeSubFolder\sublegit.txt` on Windows and
`SomeSubFolder/sublegit.txt` on Linux — **a different payload**, exercising a
different branch of every separator-based check. The matrix would compare two
different things across platforms without saying so.

**Rule: payload strings are literals, never computed.** If both separators are
worth testing they are two payloads and two rows.

Each `Payload` carries its literal, its kind, the content a correct read returns
(`null` for attacks), prose describing what the payload does, and optionally a
provenance link. The prose is authored once, next to the payload, and flows into
the report — it does not live in the README.

## 6. Expectations, with the explanation attached

```java
Expectations expected() {
    return Expectations.builder()
        .expect(LEGIT_SIMPLE_FILE, READ_OK)
        .expect(LEGIT_SUBFOLDER_FILE, SANITIZED_MISS,
            "File.getName() reduces the input to `sublegit.txt`, which does not exist at "
          + "the base directory — subdirectory access is lost, not merely denied.")
        .expect(ATTACK_WINDOWS_STYLE_TRAVERSAL,
            on(WINDOWS, SANITIZED_MISS),
            on(LINUX, UNDETECTED_MISS,
               "Backslash is a legal filename character on POSIX, so File.getName() returns "
             + "the payload unchanged and no traversal is detected."))
        .build();
}
```

The note lives **on the expectation**. Change what you expect and the
explanation is right there demanding to be updated. A separate docs file always
rots; this is the only arrangement that keeps the commentary honest.

## 7. Not chosen, and why — so this isn't re-litigated

**`demo-mode` / `dev-mode` env flag with a per-class `isVulnerable`.** Run it
against the real numbers. Dev mode inverts attack assertions for vulnerable
classes:

- `Default_NoChecks`, `ImproperPathConcat`, `Multipart` — 12 failures correctly
  absorbed.
- `Bypassable_StringContainsCheck` passes `../` and `../../` (its whole
  pedagogical point is that it is *partially* effective), so inversion turns
  those into **2 new spurious failures**.
- The 8 `EdgeLegitCase` failures on secure implementations are legit-case
  failures; the flag says nothing about them, so they **stay red**.

Dev mode lands at 10 red instead of 0 — not a usable baseline. Every patch to
the flag (`supportsSubdirectories` next, then something for `Bypassable`)
converges on the per-cell table anyway.

Two further costs: env-var-dependent pass criteria are invisible in a failure
report, so a contributor cannot tell which mode produced a red; and branching
assertions inside `BasePathProcessorTest` put two behaviours in the one file
CLAUDE.md says must never be loosened.

**Baseline-diff against committed surefire output.** Cheap and preserves demo
semantics exactly — a listener diffs each run against a committed pass/fail set.
Rejected as the destination, not as a bad idea: it keys on test-name strings and
the baseline is opaque. It remains the correct fallback if step 2 stalls.

**A separate dev-only suite.** Redundant with the matrix, except for one piece
worth doing regardless: `PathProcessor` itself — the `canSanitize` branch,
null/empty input, `joinPaths` — has no demo value and deserves plain green
tests. Not in scope here.

**Generalising the harness across vulnerability classes now.** `Outcome`'s
values (`SECRET_DISCLOSED`, `SANITIZED_MISS`) are path-traversal-flavoured.
Generalising correctly requires seeing the second vulnerability class; guessing
now would guess wrong. Revisit when XXE lands.

## 8. Platforms and containers

Split the problem — containers are needed for less than it first appears.

**Three OS families → GitHub Actions matrix, no containers.**
`windows-latest` / `ubuntu-latest` / `macos-latest`, each uploading its
`cheatcode-results/` as an artifact, with a final job merging and publishing.
Native, free for public repos, and it closes the gap that the Java build is not
currently run in CI at all. macOS earns its slot independently: the default
case-insensitive filesystem is a genuine third behaviour for path traversal.

**Linux *variants* → containers.** musl vs glibc, JDK 11/17/21, distro
filesystem semantics. Zero test-code changes — the container is just another JVM
host:

```bash
podman run --rm -v "${PWD}:/work:ro" -w /work \
  maven:3.9-eclipse-temurin-11 mvn test
```

One trap: do not bind-mount `target/` read-write from Windows into a Linux
container. Classes compiled by one platform get picked up by the other and both
runs fight over the same surefire output. Mount the source `:ro` and put build
output somewhere container-local.

**Filesystem-dependent payloads → Testcontainers, later.** Needed only when a
payload requires a filesystem `@TempDir` cannot provide: **symlink traversal**,
case-insensitive mounts, read-only or NFS mounts, `/proc` access. Symlinks are
the first target. It adds a dependency, needs a daemon, and breaks the "clone
and `mvn test`" story, so it goes behind `@Tag("container")`, excluded by
default. Under rootless Podman, Testcontainers needs
`DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock` and usually
`TESTCONTAINERS_RYUK_DISABLED=true`.

The unit-test structure survives all of this intact, because the platform
dimension lives in the **expectations** and the **merge step**, never in the
test code. The tests do not know where they are running.

## 9. Standing constraint for future maintainers

This design introduces exactly one new hazard: a regression can be "fixed" by
editing the expectation instead of the code. The rule that replaces *never
loosen the assertions*:

> **Never edit an expectation to make a run green.** Change one only with the
> evidence in the PR — the matrix diff is the reviewable artifact.

The corresponding README framing changes from "the test results are the report"
to "the matrix is the report, and the suite guards it."
