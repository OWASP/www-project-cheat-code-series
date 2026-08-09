# Debugging one case — options for how tests are declared and run

**Repo:** https://github.com/OWASP/www-project-cheat-code-series

## Status — 2026-08-09

**Decided and implemented: option 3.** All fourteen concrete test classes now
declare the seven cases as `@Test @Override` stubs, folded into a `// #region`
at the end of each file. The spike used to compare the two shapes
(`…_IndividualTests`) has been deleted.

Verified after the change: `mvn test` → 98 tests, 0 failures, unchanged;
`mvn test -Dtest='VulnerablePathProcessor_Default_NoChecksTest#AttackCase_DoubleLevelTraversal'`
→ `Tests run: 1`; the Test Explorer lists seven children per class before any
run, and **Debug Test** on one of them runs that one.

Options 1 and 2 remain useful and are kept below as escape hatches. Nothing here
changed the outcome matrix, the expectations, the report or the harness — it is
entirely about how a case is *selected* for a run.

---

## 1. The problem

The project's headline promise is that a developer can put a breakpoint on one
payload against one implementation, press **Debug Test**, and step through the
technique. In the VS Code Test Explorer that does not work: clicking one method
row under a concrete test class runs all seven cases of that class.

## 2. What was measured

Everything below was checked rather than assumed.

**It has never worked.** Every commit that has ever touched `src/test` has the
same shape — seven `@Test` methods in an abstract base class, zero in any
concrete class:

| commit | | base | subclasses |
|---|---|---|---|
| `c40e5df` | v0.01 import (`com.security.path`) | 7 `@Test` | 0 each (13 classes) |
| `e319618` | Fixed ESAPI-FileNameValidator | 7 | 0 each |
| `ad62470` | Restructure to `org.owasp.cheatcode` | 7 | 0 each |
| `03e5f5a` / `8038753` | stash — *Idea_of_passing_tests* | 7 | 0 each |
| `7d526d7` | Register all processors in Main | 7 | 0 each |
| `a193677` | Extend command injection | 7 + 14 (`BaseCommandProcessorTest`) | 0 each |
| `11e051e` | the outcome-matrix refactor | 7 | 0 each |
| `14ac7a7`, `78fd619` | since | 7 | 0 each |

The matrix refactor did not cause this, and the tooling did not change either —
`vscjava.vscode-java-test-0.46.0` was installed 2026-07-25, before that commit.

**Why the Test Explorer cannot address one case.** From the extension's language
server plugin (`com.microsoft.java.test.plugin-0.43.1.jar`):

- `TestSearchUtils.findDirectTestChildrenForClass` and `findTestItemsInTypeBinding`
  enumerate `ITypeBinding.getDeclaredMethods()` and return. There is no supertype
  walk in any searcher, so **inherited `@Test` methods are never discovered as
  children of a subclass**.
- `JUnit5TestSearcher.isTestClass` delegates to JDT's `JUnit5TestFinder.isTest`,
  which *does* consider the hierarchy — so each concrete class is correctly
  recognised as a test class, just with zero methods.
- The method rows that appear under a concrete class after a run are created by
  the result analyzer (`enlistDynamicMethodToTestMapping`) with
  `testLevel: Invocation` and the **parent class's** `jdtHandler` copied in. On
  Run/Debug the extension sends that handler to the launcher, which receives a
  class and runs all seven.

**JUnit has no such limitation.** Asking the platform what each selector resolves
to, against the real compiled test classes:

```
selectMethod(BasePathProcessorTest,  AttackCase_DoubleDotTraversal)  -> 0 test(s)
selectMethod(Secure_..._Test,        AttackCase_DoubleDotTraversal)  -> 1 test(s)
selectClass(BasePathProcessorTest)                                   -> 0 test(s)
selectClass(Secure_..._Test)                                         -> 7 test(s)
```

Line 2 is the point: an inherited method on a concrete class resolves to exactly
one test. Surefire agrees — `mvn test -Dtest='…Test#AttackCase_…'` reports
`Tests run: 1`. **The gap is discovery, not execution.**

Line 1 kills the obvious workaround: `BasePathProcessorTest` is abstract, so
debugging a method from *its* node — the one place the seven methods are
statically discovered, and the only file with gutter run icons — has always
resolved to zero tests.

**Cost of running seven instead of one is not time.** The full 98-test suite
executes in about a second; `mvn test` end to end is 4s. The ~60s a Test Explorer
run reports is JDT build and JVM launch. The only real cost is the debugger
stopping in six cases nobody asked for.

---

## 3. Option 1 — conditional breakpoint

No code change. Breakpoint on the `processor.readFile` line in
[`BasePathProcessorTest.assertCell`](../src/test/java/org/owasp/cheatcode/pathtraversal/BasePathProcessorTest.java),
condition:

```java
payload == Payload.LEGIT_SUBFOLDER_FILE
```

Then **Debug Test** on the class. All seven execute, the debugger stops only in
the chosen one, and stepping into `getResource` works normally.

- **For** — available today, zero maintenance, and picking the payload by name is
  arguably clearer than hunting a tree row.
- **Against** — it is a thing a newcomer has to be told. The PoC's audience is
  developers meeting the codebase for the first time, and "right-click the case
  you want" is the flow they will try.

## 4. Option 2 — Surefire from the CLI, attach the debugger

```bash
mvn test -Dtest='SecurePathProcessor_FileAPI_GetNameTest#AttackCase_DoubleDotTraversal' \
         -Dmaven.surefire.debug
```

plus an `attach` configuration on port 5005 in
[`.vscode/launch.json`](../.vscode/launch.json).

- **For** — genuinely one case, exactly the case named, no source changes.
- **Against** — two steps and a port; not a right-click. Good as a documented
  escape hatch, poor as the primary flow.

## 5. Option 3 — declare the seven methods in each concrete class — **adopted**

Keep the inheritance and everything the base class provides, and add seven stubs
per concrete class so the extension has something to discover:

```java
@Test
@Override
void AttackCase_DoubleDotTraversal() {
    super.AttackCase_DoubleDotTraversal();
}
```

- **For** — restores the click the PoC is built around, with no change to the
  harness, the matrix, the report or any assertion. Stubs carry no logic and
  cannot disagree with the base class. A forgotten stub is not a silent test
  loss: the inherited method still runs, it just stops being individually
  debuggable.
- **Against** — 7 × 14 = 98 methods of pure ceremony, and it contradicts the
  standing rule in [CLAUDE.md](../CLAUDE.md) that a concrete test class *never*
  adds test methods. Adding a payload becomes an edit in the base class plus a
  stub in every concrete class.
- **Variant** — bodies could be `assertCell(Payload.ATTACK_DOUBLE_DOT_TRAVERSAL)`
  instead of `super.…()`. Same discovery result; makes each file self-describing,
  at the price of restating the payload↔method mapping fourteen times where it
  can drift. The spike uses `super`, keeping the base class the single
  definition.

## 6. Option 4 — drop the base class, share a static helper

Each test class declares its seven one-line `@Test` methods directly against a
shared helper (`Cells.assertCell(processor, expectations, Payload.X)`), with no
inheritance.

- **For** — same line count as option 3 but no ceremony: each test file reads top
  to bottom, which is the argument [CLAUDE.md](../CLAUDE.md) already makes for
  the implementations in `src/main`.
- **Against** — loses what the base class is actually good at. `@TempDir`, the
  fixture, `setUp`, the recording of every cell, and the `UNDECLARED`/`MISMATCH`
  failure messages are common machinery that is genuinely easier to control from
  one place. Every one of those becomes a parameter to pass or a thing to repeat.

## 7. Option 5 — `@ParameterizedTest` / `@TestFactory`

Rejected in [test-outcome-matrix.md](test-outcome-matrix.md) on debuggability,
and that judgement stands. Recorded here only because of an irony found while
diagnosing this: the extension's `uniqueId` / `TestLevel.Invocation` machinery
exists precisely to re-run **one invocation** of a parameterized test, so the
shape the design doc rejected is the one shape whose individual cases the Test
Explorer can already address. It is still the wrong trade — a dynamic test drops
you into framework frames rather than into `getResource`, which is the code the
reader came for.

---

## 8. Decision

Option 3, with option 1 kept as a documented escape hatch.

The premise of the whole PoC is that the technique is read and stepped through,
one case at a time. 98 stub methods is a dull price, but it is paid once, it
touches nothing that can be got wrong, and it buys back the interaction the
project is named for. Option 4 buys the same thing and charges the base class's
common machinery for it — which is the part worth keeping.

Carried out on 2026-08-09:

- Seven `@Test @Override` stubs added to each of the fourteen concrete classes,
  in a `// #region` block at the end of the file so the meaningful code —
  `createProcessor`, `getProcessorName`, `describe`, `expected` — still comes
  first and the ceremony folds away.
- [CLAUDE.md](../CLAUDE.md) updated: the rule was "a concrete test class never
  adds test methods"; it is now "declares the seven cases and nothing else — no
  new payloads, no assertions of its own".
- [`BasePathProcessorTest`](../src/test/java/org/owasp/cheatcode/pathtraversal/BasePathProcessorTest.java)
  javadoc updated, including its "Debugging one case" note, which told the reader
  to run from that file's gutter — icons that resolve to zero tests, since the
  class is abstract.

Adding a payload is now: `Payload` constant, `@Test` in the base class, stub in
all fourteen classes. The last step is the one someone will forget, which is why
it is stated in CLAUDE.md as well as here.
