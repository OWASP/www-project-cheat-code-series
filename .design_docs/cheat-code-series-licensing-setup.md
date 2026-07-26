# Cheat Code Series — licensing & contribution setup

**Repo:** https://github.com/OWASP/www-project-cheat-code-series

## Status — 2026-07-26

The licensing half of this plan is **implemented**. The contribution half is
**deliberately not implemented**, and that is a decision, not an oversight for
someone reading the original plan to correct later.

The governing choice, made after this document was drafted: **do the minimum
that is legally correct, and add process only when there are contributors to
need it.** A project with no outside contributors that ships a DCO bot, a
rewritten CONTRIBUTING and a non-standard license grant has spent its
complexity budget on hypothetical problems.

| Item | Status |
|---|---|
| `LICENSE` — verbatim Apache-2.0 | Done |
| `LICENSE.md` scaffold placeholder | Deleted |
| README license section | Done |
| `project.owasp.yaml` — `license`, `type` | Done |
| Snippet supplemental grant | **Dropped** — see below |
| `NOTICE` file | **Not created** — nothing to put in it |
| DCO app, `.github/dco.yml`, CONTRIBUTING rewrite | **Deferred** |
| Warning section about deliberately vulnerable code | Deferred |

### Why the snippet grant was dropped

The plan below adds a README clause granting attribution-free reuse of the code
samples. Dropped, for two reasons:

1. **Apache-2.0 already permits copying into proprietary code.** The grant
   removed attribution *friction*; it did not unlock anything otherwise
   forbidden. A smaller benefit than the plan implies.
2. **Nobody enforces attribution over six lines of sample code**, and the
   samples are illustrative rather than drop-in ready — a developer adapts the
   approach, not the file.

Against that, a supplemental grant is non-standard text that has to live
somewhere it will actually travel with copied code. A README paragraph does not
travel; `NOTICE` does, but using it for a permission grant rather than
attribution is unconventional and would need explaining forever. Not worth it.

If reuse friction ever turns out to be real — someone actually asks — revisit
then, and put the grant in `NOTICE` rather than the README.

### Why DCO was deferred

Required by OWASP policy and worth doing before outside contributions arrive.
Deferred because there are none yet, and a DCO check is the kind of thing that
blocks a first-time contributor's PR over a missing `-s` flag. §"CONTRIBUTING.md"
and §".github/dco.yml" below remain the intended implementation for that day,
with one correction: **keep the existing CONTRIBUTING.md's OWASP Code of Conduct
link and Slack onboarding**, which the drafted replacement dropped. Merge, don't
replace.

### Deviations from the plan as written

- **No copyright line.** The plan filled the Apache appendix with
  `Copyright 2026 The OWASP Foundation and Cheat Code Series contributors`.
  That contradicts §5 of this same document: under DCO there is no assignment,
  so neither the Foundation nor the project holds contributors' copyright.
  `LICENSE` is the verbatim upstream text with the appendix template left
  unfilled, asserting no copyright — which is how most Apache-2.0 repos ship.
- **`LICENSE`, not `LICENSE.md`.** The scaffold placeholder was deleted rather
  than overwritten. Two files answering the same question is worse than one,
  and Apache's plain text renders badly as Markdown.
- **Project reclassified `documentation` → `code`** in `project.owasp.yaml` and
  `index.md` front matter, matching this document's "Project is code-type"
  premise.

---

## 1. Decisions

| Decision | Choice | Why |
|---|---|---|
| Repo license | **Apache-2.0** | OSI-approved (required by OWASP policy for code). Explicit patent grant clears enterprise OSPO review without a ticket. Strong liability disclaimer, which matters because we deliberately publish exploitable code. |
| Docs license | **Same — Apache-2.0, single LICENSE file** | Prose and code are tightly interleaved; a dual-license split creates boundary questions nobody answers consistently. Project is code-type. |
| Snippet reuse | ~~README supplemental grant~~ → **dropped** | Apache-2.0 already allows it. See Status above. |
| Contributor agreement | **DCO** (`Signed-off-by`) — deferred | Required by OWASP project policy. Enforced by the DCO GitHub App, advisory mode. Not set up until there are outside contributors. |
| Content boundary | **Theory → Cheat Sheets. Examples → here.** | Avoids maintaining duplicate canonical guidance. Each example still carries 2–3 sentences of framing so it stands alone. |

**Not chosen, and why — so this isn't re-litigated later:**

- **MIT** — shorter, but no patent grant. Defensible choice; Apache-2.0 just clears corporate review more cleanly.
- **0BSD / MIT-0** — genuinely zero-condition, but unfamiliar to SCA tools (Black Duck, Snyk, FOSSA), which flags them for manual review. More friction than the attribution clause we were avoiding.
- **CC0 / Unlicense** — CC0 is not OSI-approved, so it fails OWASP policy for code. Unlicense is poorly drafted and blacklisted by several large orgs.
- **CC BY-SA 4.0** — copyleft. Correct for the Cheat Sheets (docs project), wrong for a code corpus meant to be copied into proprietary applications.
- **Dual Apache-2.0 + CC BY 4.0 split** — considered, rejected as unnecessary ceremony for a code-type project.

**Note:** OWASP uses DCO, not a CLA. Contributors retain their copyright, and there is no entity that can relicense on their behalf. This license choice is effectively permanent once contributors arrive.

---

## 2. Files to create

### `LICENSE` — done

Full Apache License 2.0 text from https://www.apache.org/licenses/LICENSE-2.0.txt

~~Fill the copyright line in the appendix as
`Copyright 2026 The OWASP Foundation and Cheat Code Series contributors`~~ —
superseded. The appendix is left as the standard unfilled template and no
copyright is asserted; see "Deviations" above.

A `NOTICE` file is optional under Apache-2.0 and not needed here — skip it unless we later bundle third-party code that requires one.

---

### `README.md` — partially done

Shipped as:

```markdown
## License

Licensed under the [Apache License 2.0](LICENSE).
```

The supplemental snippet grant was **dropped** — see Status above. The warning
section below is still worth adding; deferred only to keep the licensing commit
focused.

```markdown
## ⚠️ Warning

This repository contains deliberately vulnerable code for educational and
testing purposes. Do not deploy the vulnerable samples to any environment
reachable from an untrusted network.
```

`SECURITY.md` needs the same treatment when that lands: it currently says to
report security issues to the project leaders, which invites reports about
vulnerabilities planted on purpose. It should scope those out and say what *is*
worth reporting — a "secure" implementation that does not actually hold.

---

### `CONTRIBUTING.md` — deferred

Not applied. When it is, **merge this into the existing file** rather than
replacing it — the current CONTRIBUTING.md carries the OWASP Code of Conduct
link and Slack onboarding that the draft below omits.

```markdown
# Contributing

## Sign-off (DCO) — required

All commits must carry a `Signed-off-by` line certifying you have the right
to submit the contribution. See https://developercertificate.org/

Add it automatically with `-s`:

    git commit -s -m "Add SQL injection samples for Java"

One-time setup:

    git config --global user.name "Your Name"
    git config --global user.email "you@example.com"
    git config --global alias.cs "commit -s"

### If the DCO check fails

The most common cause is an **email mismatch**: the sign-off email must match
the commit author email, and that email should be verified on your GitHub
account.

1. Check what git is using: `git config user.email`
2. Confirm that address is listed and verified under
   GitHub → Settings → Emails.
3. If you have "Keep my email address private" enabled, use your GitHub
   noreply address instead:
   `git config --global user.email "ID+username@users.noreply.github.com"`
   (find your exact address on the same settings page)

Always use `git commit -s` rather than typing the `Signed-off-by` line by
hand — hand-typed lines are where mismatches come from.

**Fixing commits already pushed:**

    # single commit
    git commit --amend -s
    git push --force-with-lease

    # several commits
    git rebase --signoff HEAD~3
    git push --force-with-lease

Editing files through the GitHub web interface does not add a sign-off.
Use a local clone for anything beyond trivial changes.

## Content provenance — required

Every contribution must be original work.

- **Do not paste from other projects.** This includes the OWASP Cheat Sheet
  Series, which is CC BY-SA 4.0 — ShareAlike is incompatible with this
  repository's Apache-2.0 license. Read it, close the tab, write your own.
- **Link, don't quote.** Reference the relevant Cheat Sheet by URL rather
  than reproducing its text. Links stay current; copies drift.
- **Check the license of any payload set** before vendoring it (including
  PayloadsAllTheThings). Open the LICENSE file — do not assume.
- Ideas, techniques and facts are free to use. Only the specific wording and
  the specific code as written are owned by their authors.

## What each example should include

- The vulnerable implementation
- One or more secure implementations
- Attack payloads as pass/fail tests
- 2–3 sentences of framing: what the flaw is, why the fix works, what the
  payloads prove
- A link to the relevant OWASP Cheat Sheet for the full explanation

Keep the framing short. Detailed guidance belongs in the Cheat Sheets, not
here — but every example must be understandable on its own without following
the link.
```

---

### `.github/dco.yml` — deferred

```yaml
allowRemediationCommits:
  individual: true
```

Lets a contributor fix a missing sign-off by pushing a follow-up commit
instead of force-pushing a rewritten history. Friendlier for first-time
contributors.

Leave `thirdParty` off. It allows someone to sign off on another person's
behalf, which requires verifying an employment or agency relationship — not a
judgement call we want to be making ad hoc.

---

## 3. GitHub settings checklist

Every DCO item here is deferred with the DCO decision above. The last two are
live.

- [ ] Install the DCO app: https://github.com/apps/dco — enable for this repo
- [ ] Leave the check **advisory** (do *not* add it to required status checks yet). At current contribution volume we will notice every failure manually, and a hard block on a first-time contributor's PR is a good way to lose them. Revisit once there are regular outside contributors.
- [ ] Settings → General → enable **"Require contributors to sign off on web-based commits"** — adds the sign-off automatically to browser edits, which otherwise always fail the check
- [ ] Confirm GitHub shows the license as "Apache-2.0" in the repo sidebar after pushing the LICENSE file
- [ ] Update the project page on owasp.org to state the license

Bots and merge commits are excluded from the DCO check by default — Dependabot will not break.

---

## 4. Optional, later

**REUSE / SPDX headers** (https://reuse.software) — SPDX comment headers on every file plus a `LICENSES/` directory, with a CI linter verifying nothing is unaccounted for.

Not needed now. Becomes worth it once the repo has mixed-provenance content or crosses ~100 files, because it turns "which license covers this file?" from archaeology into a build check. If we ever do need to include CC BY-SA material, this is the mechanism that quarantines it cleanly:

```java
// SPDX-License-Identifier: CC-BY-SA-4.0
```

---

## 5. Standing constraint for future maintainers

Because contributions come in under DCO rather than a CLA, **each contributor keeps their own copyright**. Neither the project leads nor the OWASP Foundation can relicense this repository unilaterally. Changing the license later would require locating and obtaining consent from every contributor.

Treat Apache-2.0 as permanent.

---

## 6. Related plan

A Path Traversal cheat sheet is planned as a contribution to the OWASP Cheat
Sheet Series once the corresponding examples here are complete, cross-linking
to this repository.

**Important:** the Cheat Sheets are CC BY-SA 4.0, and license compatibility
runs one way — our content can flow *into* them, but nothing can flow back.
As the author of that cheat sheet you may use your own text anywhere you
like, but **keep your original draft locally** and reuse from that copy.
Once the cheat sheet is merged and other people edit it, their edits are
CC BY-SA and belong to them, and copying the merged version back into this
repository would be a license violation.
