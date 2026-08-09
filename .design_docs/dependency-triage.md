# Cheat Code Series — Dependency Triage Record

Status: **13 of 14 alerts fixed; 1 remains, provably unreachable.**
Scope: the Java PoC's `pom.xml`. Written 2026-08-09 against the Dependabot alert set on `main`
(1 critical, 8 high, 3 moderate, 2 low).

A project whose subject is the difference between a defence that works and one that merely
looks like it works should not resolve its own alerts by reflex. This records what was
upgraded, what was excluded, and — for the survivor — the evidence that the vulnerable code
cannot be entered from this repository.

---

## 1. What changed

| Dependency | Was | Now | Why |
|---|---|---|---|
| **Java** | 11 | **17** | Spring 7's floor. Nothing in this PoC needs 17 on its own. |
| `spring-web`, `spring-test` | 5.3.27 | **7.0.8** | Clears 4 advisories including the critical. See §2. |
| `esapi` | 2.6.0.0 | **2.7.0.0** | Pulls patched `commons-beanutils` and `antisamy`. |
| `commons-fileupload` | 1.5, direct | 1.6.0, via ESAPI | Direct declaration removed — nothing in `src/` imports it. |
| `commons-io` | 2.11.0 | 2.19.0 | Transitive; followed `antisamy` 1.7.8. |
| `commons-beanutils` | 1.9.4 | 1.11.0 | Transitive; followed ESAPI 2.7.0.0. |
| `httpclient5` | 5.4.1 | 5.4.4 | Transitive; followed `antisamy` 1.7.8. |
| `commons-configuration` | 1.10 | **excluded** | EOL, unfixable, and unreachable. See §3. |

Every version in the resulting tree was checked against the GitHub advisory database, including
the dependencies Spring 7 newly introduces (`jspecify`, `micrometer-observation`,
`micrometer-commons`). The upgrade introduces no new alerts.

### The upgrade is behaviour-neutral

`mvn test` stayed at 105 tests / 0 failures with `MATCH=105` at every step, and the regenerated
`results-table.md` is byte-identical to the one in the README. No cell moved, so no expectation
was touched, so the published matrix needs no edit.

That check is not a formality. Two of these changes could plausibly have moved a cell:

- **ESAPI 2.6 → 2.7** is a minor-version bump of the library behind three `Secure_*` validators.
  It reclassified nothing; all 21 ESAPI cells hold.
- **Spring 5.3 → 7.0** could have killed an exhibit outright. If `getOriginalFilename()` had
  started stripping path information, `Vulnerable_None_Spring_GetOriginalFilename_FalseSanitizer`
  would have stopped demonstrating anything. It has not: Spring 7 still returns the client's
  string verbatim, separators and all, and the class remains matrix-identical to
  `Vulnerable_None_JavaNIO_PathsGet_NoDefence`. **The trap is current, not historical** — worth
  saying in the exhibit's own terms, since a reader may assume a decade-old warning has been
  fixed by now.

### `javax.servlet-api` looks removable and is not

Nothing in `src/` imports `javax.servlet`, so it reads as dead weight. It is not: ESAPI's
validator loads `javax.servlet.http.HttpServletRequest` at runtime, and removing the dependency
fails all 21 ESAPI cells with `NoClassDefFoundError`. ESAPI declares it `provided`, which is why
the consumer has to supply it. Note it stays on the **`javax`** namespace while Spring 7 is on
**`jakarta`** — the two coexist without conflict because they are different packages, and Spring
7 needed no `jakarta.servlet-api` here since `MockMultipartFile` does not load servlet types.
It carries no alerts. This was tested, not assumed.

---

## 2. Why Spring 7.0.8 specifically

Four advisories, and the patched-version ranges do not overlap the way one would guess:

| Advisory | Needs |
|---|---|
| GHSA-4wrc-f8pq-fpqp (critical, CVE-2016-1000027) | ≥ 6.0.0 |
| GHSA-4gc7-5j7h-4qph (medium, CVE-2024-38820) | ≥ 6.1.14 — **no fix on 6.0.x** |
| GHSA-jmp9-x22r-554x (high, CVE-2025-41249) | ≥ 6.2.11 — **no fix on 6.1.x** |
| GHSA-659m-px2c-25wj (low, AntPathMatcher ReDoS) | ≥ 6.2.19 or ≥ 7.0.8 — **no fix on 6.1.x** |

So the 6.0 and 6.1 lines are not landing spots at all: each leaves at least one advisory with no
available fix. The minimum version clearing all four is **6.2.19**; 7.0.8 is the current GA and
was chosen for headroom. Both require Java 17, so the floor moves either way.

**The Java 11 floor was the real cost, and it was accepted deliberately.** This is a
single-maintainer proof of concept, not a library with downstream consumers, so the floor is
cheap to move — which is the only reason the trade came out this way. A library shipping to
unknown consumers should weigh it differently, and might well conclude that four advisories in
code paths it does not contain are worth carrying rather than forcing 17 on everyone.

---

## 3. `commons-configuration` — excluded, not dismissed

commons-configuration 1.x is EOL with an open advisory (GHSA-pvp8-3xj6-8c6x, CVE-2025-46392) that
its maintainers have stated they will not fix in the 1.x line. ESAPI 2.7.0.0 still depends on
1.10, and so does 2.7.0.1-RC1, so no ESAPI upgrade clears it.

Inspecting the ESAPI jar, the only classes referencing it are:

```
org/owasp/esapi/reference/accesscontrol/policyloader/ACRParameterLoader.class
org/owasp/esapi/reference/accesscontrol/policyloader/ACRParameterLoaderHelper.class
org/owasp/esapi/reference/accesscontrol/policyloader/ACRPolicyFileLoader.class
org/owasp/esapi/reference/accesscontrol/policyloader/DynaBeanACRParameterLoader.class
```

All four belong to ESAPI's access-control subsystem. This project uses `Validator` and
`SecurityConfiguration` and never calls `ESAPI.accessController()`, so the jar is dead weight
here. Excluding it removes the alert honestly rather than arguing it away, and the full suite
plus `Main` run clean without it. **If anything ever calls `ESAPI.accessController()`, put it
back** — the `pom.xml` exclusion carries that same warning.

---

## 4. The one that remains

| Severity | Advisory | Package |
|---|---|---|
| medium | GHSA-j288-q9x7-2f5v (CVE-2025-48924) | `commons-lang` 2.6, via ESAPI |

The vulnerability is an uncontrolled recursion: `ClassUtils.getClass(...)` throws
`StackOverflowError` on very long input. commons-lang 2.6 is the final release of the 2.x line
and the fix exists only in `commons-lang3` 3.18.0 — a different package name, so ESAPI's bytecode
references could not resolve against it even if it were substituted.

It cannot be excluded: `org.owasp.esapi.reference.DefaultSecurityConfiguration` genuinely uses it,
and that class is on this project's path.

**But the vulnerable class is never loaded.** ESAPI's only reference into commons-lang is
`org.apache.commons.lang.text.StrTokenizer`, and `ClassUtils` does not appear anywhere in the
ESAPI jar:

```
$ javap -p -c org/owasp/esapi/reference/DefaultSecurityConfiguration.class | grep -o 'org/apache/commons/lang/[A-Za-z/]*' | sort -u
org/apache/commons/lang/text/StrTokenizer

$ grep -rl "org/apache/commons/lang/ClassUtils" --include=*.class .
(no matches)
```

That is a stronger claim than "we do not hit that path": there is no call site anywhere in the
dependency that could reach the vulnerable method. Beyond that, the PoC opens no port and
processes seven hard-coded payload literals from
[Payload.java](../src/test/java/org/owasp/cheatcode/pathtraversal/Payload.java), the longest of
which is 34 characters.

Dismiss in the GitHub UI as *"Vulnerable code is not actually used"*, citing this section. The
upstream fix belongs in ESAPI — moving `DefaultSecurityConfiguration` off `StrTokenizer`, or onto
`commons-lang3` — and is worth reporting there rather than working around here.

---

## 5. Rejected alternatives

**Drop Spring, hand-roll `MultipartFile`.** Clears the four Spring alerts at no Java-version cost,
and was rejected anyway. The `FalseSanitizer` exhibit is matrix-identical to
`Vulnerable_None_JavaNIO_PathsGet_NoDefence` on all seven payloads — its entire value is that
`getOriginalFilename()` is a *real, recognisable framework API* that reads like a sanitizer and is
not one. Against a locally-defined interface the class would be asserting the trap instead of
demonstrating it, and a reader could fairly answer "you wrote that stub to lose." The dependency
is the evidence.

**Move Spring to `test` scope.** Would not clear the alerts — Dependabot reads the manifest, not
the scope — and the class lives in `src/main`, which is the exhibit. Scope is not a security
control.

**Exclude `commons-lang` too.** Would take the count to zero and break
`DefaultSecurityConfiguration` at runtime, trading a documented, unreachable advisory for an
undocumented `NoClassDefFoundError`. Zero alerts is not the goal; an accurate posture is.
