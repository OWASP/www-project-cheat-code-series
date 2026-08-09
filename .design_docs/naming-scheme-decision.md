# Cheat Code Series — Naming Scheme Decision Record

Status: **decided**, one slot deferred (validator/sanitizer).
Scope: file/class naming for code examples. Written against path traversal;
slot *semantics* apply series-wide, slot *vocabulary* is defined per vulnerability class.

---

## 1. Three verdict tiers

The boundary is **what an attacker needs in order to exploit it**:

| Tier | Definition |
|---|---|
| `Secure` | No known bypass, and no precondition outside the snippet. |
| `ConditionallySecure` | Not defeated by any payload. Exploitation requires an **environmental precondition** the snippet cannot control — config, filesystem state, platform, or caller behaviour. |
| `Vulnerable` | Defeated by a **different payload alone**, against the same deployment. Nothing about the environment needs to change. |

The test: *can an attacker with only the request break this?*
Yes → `Vulnerable`. No, they also need something else to be true → `ConditionallySecure`.

### Hard rules

- **Functional restrictiveness does not demote a file.** A whitelist that blocks
  subfolders or rejects legitimate filenames stays `Secure`. The limitation goes in
  the header block, never in the name.
- **Symlink-following is `ConditionallySecure`, not `Vulnerable`.** Exploitation needs
  an attacker-placed symlink to exist; no payload alone achieves it.
- **Config dependence is `ConditionallySecure`.** ESAPI's whitelist is only as good as
  the pattern in `validation.properties`, which is not in the file.
- Vocabulary is fixed: **`Vulnerable`**, never `Insecure`.

---

## 2. Filename format

```
{Verdict}_{Strategy}_{Library}_{Variant}.java
```

- Underscore-separated, full words, no abbreviations.
- `PathProcessor` infix **dropped** — already stated by the package.
- Acronyms keep conventional casing: `ESAPI`, not `Esapi`.
- Scaffolding (`Main`, `PathProcessor`, `ReadFileResult`) carries **no verdict prefix**.

```
Secure_ResolvedPath_JavaNIO_ToRealPathStartsWith
Secure_RawString_JavaFileAPI_GetName
Secure_RawString_Regex_WhitelistAlphaNumericDot
ConditionallySecure_RawString_ESAPI_FileName
ConditionallySecure_LexicalPath_JavaNIO_NormalizeStartsWith
Vulnerable_RawString_Regex_Blacklist
Vulnerable_RawString_StringOps_Contains
Vulnerable_None_Manual_DirectConcat
```

### Slot semantics

| Slot | Question it answers | Classification test |
|---|---|---|
| Verdict | May I use this? | See §1 |
| Strategy | **What does the code decide on?** | Which resolution call precedes the decision |
| Library | What do I call? | The API surface |
| Variant | Which flavour of that call? | Free text, per-library |

### Strategy vocabulary (path traversal)

| Value | Meaning | Symlink-safe? |
|---|---|---|
| `RawString` | Operates on the untrusted string; no `..` resolution of any kind | n/a |
| `LexicalPath` | Resolves `..` in-memory only (`normalize`, `relativize`) — never touches disk | **No** |
| `ResolvedPath` | Resolves against the filesystem (`getCanonicalPath`, `toRealPath`) | Yes |
| `Indirection` | Never accepts a path — ID maps to a file | Yes |
| `None` | No decision made | No |

**A library is never a strategy.** ESAPI and the JDK File API are wrappers; classify by
what they wrap. ESAPI file-name validation is a whitelist regex over the string →
`RawString`. `File.getName()` does no resolution → `RawString` (it is secure because it
*discards* the directory portion, not because it resolves anything — state this in the
header, or a reader will assume `getName()` resolves and misuse it elsewhere).

---

## 3. Underscores: deliberate deviation

Idiomatic Java is UpperCamelCase with no underscores (Oracle convention, Google Java
Style, Checkstyle default `TypeName`). This project deviates on purpose.

**Rationale:** underscores make the four slots pre-attentive — structure is visible
before the words are read. The generated HTML report renders filenames directly, so
slot legibility and a visible verdict are load-bearing in the primary reader-facing
artifact, not just in the file tree.

**Cost accepted:** the library models a style violation to an audience of Java
developers; contributors' IDEs will flag it.

- [ ] Checkstyle suppression for `TypeName` under the examples package
- [ ] Deviation documented in `CLAUDE.md` and `CONTRIBUTING.md` with the rationale above

---

## 4. Header block (mandatory, every example file)

The name carries the verdict; the header carries everything that can change.

```
Strategy:          RawString | LexicalPath | ResolvedPath | Indirection | None
Precondition-Type: (ConditionallySecure only — free text for now, see §6.2)
Preconditions:     (what must be true outside this file, specifically)
Limitations:       (functional cost: no subfolders, rejects Unicode, etc.)
Known bypasses:    (Vulnerable only — the specific payload and why it works)
Platform:          (if behaviour differs across OS)
```

**Preconditions must be specific.** Not "depends on ESAPI config" but
`Validator.FileName` in `validation.properties`. Not "symlinks" but *"attacker can
place a symlink inside the base directory — e.g. via archive extraction, since zip/tar
entries can themselves be symlinks (zip slip), which needs no shell access."*

Verdicts change over time — a bypass gets published, an ESAPI default shifts. Headers
can be edited; filenames become public URLs once the Cheat Sheets cross-reference
lands, and cannot.

---

## 5. Re-classification audit — do before anything is public

- `RelativePath_Validation`, `RelativeToBaseFolder_Validation` — **check first.** If
  they use `normalize()` without `toRealPath()`, they are `LexicalPath` and
  `ConditionallySecure` (symlink precondition), not `Secure`.
- `Regex_Blacklist_Simple`, `Regex_Blacklist_Extended` — canonical bypassable
  approach; payload alone defeats them → `Vulnerable`.
- `StringContains_Simple` — confusingly close to the existing
  `Vulnerable…Bypassable_StringContainsCheck`. Resolve or merge.
- `ESAPI_FileNameValidation` vs `ESAPI_DefaultFileNameValidation` — if the difference
  is stock vs custom config, that is the Secure / ConditionallySecure boundary; if it
  is two different ESAPI calls, it is slot 4.
- Failure-reason prefixes (`Bypassable`, `ImproperAPIUse`, `Default_NoChecks`) move
  out of names and into `Known bypasses:`. Slot 2 must mean the same thing in every
  tier, or vulnerable/secure variants of one approach cannot be lined up.

**Likely gap:** if `ResolvedPath` and `Indirection` come back nearly empty, the library
currently has three tiers of string-checking and few examples of the two approaches
that actually work. That gap is more valuable news than the naming decision.

---

## 6. Open questions

### 6.1 Validator / sanitizer slot — **undecided, deferred**

Whether to add a 5th slot: `ConditionallySecure_RawString_ESAPI_FileName_Validator`.

**Against (current lean):** it is *derivable* from slot 4 if vocabulary stays
disciplined — `Blacklist`/`Whitelist`/`FileName` reject, `Strip`/`Normalize`/`GetName`
transform. It is also the least predictive attribute: strategy predicts the verdict,
kind does not (both validators and sanitizers fail on raw strings and hold on resolved
paths). Five slots invites inconsistent filling.

**For:** the reject-vs-transform distinction drives the classic `....//` bypass, so it
is real teaching content, and an explicit slot is greppable.

**Interim:** carry it as a header field and an HTML report column. Promote to slot 5
later only if the report shows it is actually used for filtering. Adopting later is a
bulk rename across public URLs — so decide before the Cheat Sheets cross-reference.

### 6.2 `Precondition-Type` standardisation — deferred

Free text for now. `ConditionallySecure` will be the largest tier and holds
structurally different things — config-dependent (ESAPI) vs environment-dependent
(symlinks). Candidate enum once patterns emerge: `Config | Environment | Caller |
Platform`. That subdivision is what a reader deciding "can I ship this?" actually needs.

### 6.3 Enforcement — deferred by decision

No enums-in-code and no CI filename validation while the project has a single
maintainer. Note the cost lands later: slot 4 is free text and will drift
(`Blacklist` / `BlackList` / `Denylist`) once others contribute. A ~10-line filename
regex over slots 1–3 is the cheapest insurance when that day comes.

### 6.4 Other

- Does the strategy vocabulary survive contact with the next vulnerability class
  (SQLi, XSS)? Slot semantics should; word lists will not.
- Does the HTML report group by verdict or by strategy? If it can group by strategy,
  the "tree as argument" effect works regardless of alphabetical filename order.
- `getCanonicalPath()` is check-then-use and TOCTOU-racy where an attacker can swap
  the path between check and open. `toRealPath()` plus `NOFOLLOW_LINKS` on open is the
  tighter form — worth a dedicated `ResolvedPath` pair.
