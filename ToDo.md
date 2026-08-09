# ToDo

Parked ideas, with enough context to pick them up cold. Nothing here is a
commitment — this is the holding area for things deliberately deferred.

---

## Review every `Validator` against the "validation is the recommendation" philosophy

**Status:** parked 2026-08-09.

The design position, now recorded in `CLAUDE.md`: **validation is what production code
should do; sanitization is a fallback.** A sanitizer silently changes which file gets
read, so the application serves something the caller never asked for and no error is
raised anywhere. That is a predictability cost, not just a security one — and it is
paid on legitimate input too.

`Secure_RawString_Regex_AllowAlphaNumericDot_Validator` was converted first, as the
strongest production-recommendable example. The rest need the same pass:

- The three ESAPI validators already refuse rather than repair — confirm that is by
  design and not an accident of `getValidFileName` throwing, and say so in the header.
- The two `ResolvedPath` validators refuse correctly but read the raw input afterwards
  (see the check-then-use item below) — the philosophy argues they should read the path
  they validated.
- Each remaining `Sanitizer` needs an explicit reason to exist: which real constraint
  makes repair the only option there? If none can be named, it is a counter-example
  rather than a recommendation, and its header should say that outright.

The pair pattern is the tool for this — `ContainsDotDotSlash_Validator` against
`ContainsDotDotSlash_Sanitizer` shows the cost of repair on one cell. A second pair
around the alphanumeric allow-list would show the *silent* cost: the validator refuses
`SomeSubFolder/sublegit.txt` loudly, while the sanitizer reads
`SomeSubFoldersublegit.txt` and reports nothing wrong.

---

## Add `Indirection` and `LexicalPath` examples

**Status:** parked 2026-08-09. This is the biggest content gap in the library.

Of fifteen implementations, twelve are `RawString` and three are `None`. Two of the
five strategies have **no example at all**, and one of them is the approach that
actually works:

- **`Indirection`** — never accept a path. The request carries an opaque ID; the code
  maps it to a file through a lookup it controls. No payload can express a traversal
  because no part of the input reaches the filesystem. Zero examples. This is the
  strongest remediation in the vocabulary and the library does not demonstrate it.
  Needs a fixture that holds the ID→file mapping, and probably a payload or two that
  are IDs rather than paths.
- **`LexicalPath`** — `Path.normalize()` and `relativize()`, resolving `..` in memory
  without touching the disk. Zero examples. Worth having precisely because it *looks*
  equivalent to `ResolvedPath` and is not: normalize is symlink-blind, so it is a
  `ConditionallySecure` candidate the moment a symlink payload exists.

Until both land, the library is three tiers of string-checking plus two canonical-path
validators, and the README table understates what a developer should actually reach for.

---

## Promote `ConditionallySecure` to a third verdict tier

**Status:** parked 2026-08-09. Blocked on the payload work below — do that first.

`.design_docs/naming-scheme-decision.md` §1 defines three tiers. The rename adopted
only two, `Secure` and `Vulnerable`, on purpose: naming a class
`ConditionallySecure` asserts a precondition (a symlink, a TOCTOU race, a config
value) that no payload in the suite exercises. That is the same guessing the project
already forbids for undeclared platforms — an expectation written before the run.

**Candidates, once there is evidence:**

- `Secure_ResolvedPath_JavaFileAPI_CanonicalVsAbsolute_Validator` — canonicalises
  against the process working directory and never looks at the base directory at all,
  so a symlink placed inside the base directory is never examined. Symlink precondition.
- `Secure_ResolvedPath_JavaFileAPI_CanonicalStartsWithBase_Validator` — validates a
  resolved path, then re-resolves the raw input for the read. TOCTOU precondition.
- The three ESAPI validators — every one of them, including the "Default" variant that
  hard-codes its extension list, still gets its filename pattern from
  `Validator.FileName` in `src/main/resources/esapi/ESAPI.properties`. Config
  precondition. Note the decision record's §5 gets this wrong: it suggests the
  hard-coded/config difference is the Secure/ConditionallySecure boundary, when in fact
  *all three* are config-dependent and the difference is slot 4.

**Cost when it lands:** the tier is currently derived by
`cell.implementation.startsWith("Vulnerable")` into a boolean `vulnerableByDesign`
(`BasePathProcessorTest`), consumed by `HtmlReport`, `MarkdownReport` and
`ReportGenerator`. Three tiers means boolean → enum in those four places, plus the
README grouping. Also: a `-Dtest='Secure*Test'` glob stops matching
`ConditionallySecure*Test`.

---

## Expand the `ResolvedPath` family into a check-then-use pair

**Status:** parked 2026-08-09. Do after the validator/sanitizer clarification lands.

Today there are exactly two implementations that resolve against the filesystem,
and both are `java.io.File.getCanonicalPath()`:

- `Secure_ResolvedPath_JavaFileAPI_CanonicalVsAbsolute_Validator` — canonicalises `new File(userInput)`,
  which resolves against the **process working directory**, not `baseDirectory`, and
  then reads `Paths.get(baseDirectory, userInput)`. The check and the use have
  different roots; the base directory is never examined at all.
- `Secure_ResolvedPath_JavaFileAPI_CanonicalStartsWithBase_Validator` — canonicalises the joined
  path against the canonical base directory, correctly — and then **discards that
  answer** and re-resolves the raw input for the read.

Both are check-then-use. The second is one line away from being the good example.

**The pair to build:** two implementations that differ only in whether the path
they validated is the path they read.

1. Validates a resolved path, then reads the *raw* input (today's shape) — TOCTOU-racy.
2. Validates a resolved path, then reads *that same resolved path* — the tight form.
   Tighter still: `toRealPath()` plus `NOFOLLOW_LINKS` on open, per
   `.design_docs/naming-scheme-decision.md` §6.4.

**The blocker, and why this is worth doing properly:** the current payload set
cannot tell the two apart. A payload that distinguishes them has to change the
filesystem between the check and the read — a symlink swap, or a directory
replaced mid-flight. That needs a payload concept the harness does not have yet:
today a `Payload` is a string literal, and this one is a *string plus an action
performed between validate and read*. Designing that extension is the real work
here, not the two classes.

Same gap covers the symlink precondition that makes `RelativePath_Validation`
`ConditionallySecure` rather than `Secure`. Until a payload exercises it, that
tier is an assertion the suite does not check.

**Trap to fix before building either one:** `OutcomeClassifier.inputRewritten` decides
"did this implementation rewrite the input?" with plain `Path.equals` against
`Paths.get(base, rawInput)`. An implementation that reads the canonical path it just
validated names *the same file by a different string*, and the classifier would call
that a rewrite - flipping `READ_OK` to `SANITIZED_HIT` and `UNDETECTED_MISS` to
`SANITIZED_MISS`, and reporting a pure validator as a sanitizer. The question the
harness means to ask is "did it read a different **file**", so the comparison wants
`normalize()` on both sides, or `Files.isSameFile` where the file exists. This has not
bitten yet only because no implementation currently reads a resolved path.

**Also missing entirely:** `Indirection` (an ID mapped to a file, never accepting
a path) has zero examples, and `LexicalPath` (`normalize()` without touching the
disk) has zero. Twelve of fourteen implementations are `RawString`. The library
currently has three tiers of string-checking and almost nothing of the two
approaches that actually work.
