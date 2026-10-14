# Terminal221b case contract: threat model

**Status:** review of the shipped Phase 0/1 slice, not a future design.
**Date:** 2026-09-30.
**Scope reviewed:** `packages/cli/src/case.ts`, `case-fixtures.ts`, `ranking.ts`, `dossier.ts`, and the `case` verbs in `packages/cli/src/cli.ts`.
**Gate:** the third Phase 0 gate item in [TERMINAL221B-SYSTEM-ARCHITECTURE.md](TERMINAL221B-SYSTEM-ARCHITECTURE.md) §11, alongside the schema tests and the provenance invariants.
**Passes:** three. The first two closed F1–F14; the third closed F4, F5, and F6 and found F18–F20 while doing it.

## 1. What this slice is, and what it is not

The slice is a **pure, offline reader and renderer** for a local case bundle: a JSON file on disk, parsed by fail-closed validators, checked for provenance, ranked by an ordinal gate, and printed as markdown.

Verified by reading the modules, not assumed:

- `case.ts` imports `node:fs/promises`, `node:path`, and `./scope.js`. `case-fixtures.ts` additionally imports `node:crypto`. `ranking.ts` and `dossier.ts` import nothing outside `./case.js`, `./scope.js`, and each other. No `fetch`, no `node:http`, no `node:net`, no child process.
- The `case dossier` path never reads `ANTHROPIC_API_KEY` and never calls a provider. It reads one file the operator names and writes markdown to stdout.
- There is no credential, token, seed phrase, or key field anywhere in the six schemas. A key cannot be persisted through this contract because there is nowhere to put it.

So the asset at risk is not a signing key and it is not the operator's files. It is **the operator's judgment**: whether a case presented as ready for review actually is, and whether the record shown to them is a faithful account.

## 2. Trust boundary

| Side | Trust | Notes |
|---|---|---|
| The code in `packages/cli/src` | Trusted | This is the boundary being enforced. |
| The local operator | Trusted | The only party allowed to approve or record an outcome. |
| The bundle JSON on disk | **Untrusted** | Hand-edited, imported from another machine, or later written by an adapter. Treated as attacker-controlled input. |
| Imported text inside the bundle | **Untrusted** | `claim`, `objective`, `effect`, and `uri` are free text that may originate from a program page or a scanner. |
| A remote program or target | **Not reachable** | No code path in this slice performs egress. |

The threat model is therefore: *a hostile bundle is placed on disk and the operator renders it.*

## 3. Controls enforced, with the code and test that enforce them

| Blueprint rule | Enforcement | Test |
|---|---|---|
| §3.3 Sign/transfer not in MVP; never store signing keys | `parseTaskContract` rejects `capability: 'sign_transfer'` before the enum check; `sign_transfer` is absent from `CAPABILITIES`, so no other value reaches it | `case.test.ts` |
| §3.3 Capability is granted per task, not per role | `writablePaths` non-empty requires `modify` or `submit_publish` | `case.test.ts` |
| §3.1 Deterministic check or human review before promoting a claim to accepted evidence | `parseEvidenceRecord` rejects `claimType: 'fact'` with `verification: 'unverified'` | `case.test.ts` |
| §3.1 An agent never approves or records its own outcome | `decidedBy` and `recordedBy` are typed the literal `'human'`; any other value throws | `case.test.ts` |
| §4.1 A published reward is not payment | `parseOutcomeRecord` requires `receiptReference` when `disposition` is `paid` | `case.test.ts` |
| §3.4 Cost estimates are labelled as estimates | `actualCostUsd.source` is required and enumerated | `case.test.ts` |
| §3.2 Unknown structured output fails closed | `assertKnownKeys` rejects any unrecognised field, so a typo or a smuggled field is an error rather than a dropped value | `case.test.ts` |
| §3.4 Explicit retention per source | `retention` is a required enumerated field, never defaulted | `case.test.ts` |
| §7.3 Scope is exact, wildcards rejected | `isTargetInScope` runs the target through `scope.ts` `parseTarget`, which rejects `*`, non-HTTPS, embedded credentials, query, and fragment, and requires an exact `origin` match | `ranking.test.ts` |
| §7.3 Unknowns never score as favourable | `LEVEL_RANK.unknown` is 0, the lowest; four factors stay `unknown` because the bundle cannot determine them | `ranking.test.ts` |
| §7.3 No payout probability or weighted score | No such value exists in the code. There is no numeric aggregate to misread as expected value. | `ranking.test.ts`, dossier footer |
| §3.2 Provenance must resolve | `validateCaseBundle` reports every unresolved case, source, evidence, task, approval, and outcome link | `case.test.ts`, `ranking.test.ts` |
| §3.3 A human act is signed by a key, not typed into a field | `signRecord`/`verifyRecord` produce a detached ed25519 signature over the record's canonical JSON; the store refuses any bundle carrying an unsigned human record, and `evaluateEligibility` emits `confirmation_unsigned` for a confirmation nobody signed | `store.test.ts`, `ranking.test.ts` |
| §3.4 A digest is computed, not trusted | `checkSourceDigests` hashes the local bytes of every `file://` and `local://` source and refuses a put whose bytes disagree with `contentDigest`; `verifyStore` re-reads them on every verification | `store.test.ts` |
| §3.3 A task may not declare a path outside its workspace | `assertDeclarablePath` runs over every `writablePaths` entry inside `parseTaskContract`, so a traversal, absolute, quote, backslash, `.git`, or sensitive path fails to parse | `path-guard.test.ts`, `case.test.ts` |
| §3.2 A stored bundle must be the bundle that was signed | `putBundle` verifies before it writes anything, claims its revision with an exclusive create (no lock; a concurrent writer cannot replace it), and records the bundle digest in the writer's `transitions.d/` log; `verifyStore` and `getBundle` (including an explicit revision) compare the bytes against the recorded digest rather than against a digest recomputed from the same bytes, and refuse a revision nothing vouches for; migration of a v1 store happens only if `<store>/.lock` does not exist, and otherwise refuses and changes nothing (upgrading while an older CLI may be writing is unsupported); `verify` reports objects no vouched revision references and any unusable trusted key. Not covered: an older CLI that is running when the store is upgraded and has no `.lock` file at that moment, a no-link filesystem on which a lost create reply leaves a complete but unvouched revision (reported by `verify` on every run), and its `retention --record-default-policy`, which can still replace `retention.json` (see the ADR) | `store.test.ts` |
| §3.4 A retention class is acted on, not just recorded | `retentionReport` ages every stored source against the window its class carries, reports a class with no window as `unconfigured` rather than as safe, and never marks the newest revision purgeable; `purgeExpired` refuses a token that does not match the store as it is now, removes whole revisions rather than records so no surviving signature is falsified, and deletes a content-addressed object only once no surviving revision points at it | `store.test.ts` |
| §6.4 A provider request is cancellable and its failures stay distinct | `ClaudeService.sendMessage` builds an `AbortController` timeout by hand and passes the `signal`; the transport catch returns a typed `ProviderFailure` (`timeout` when the signal fired, `network` with the cause otherwise), a non-`Error` throw is typed rather than discarded, an unparseable error body keeps its status, and a whitespace-only text block is a refusal rather than an empty success | `ClaudeService.test.ts` |
| §3.3 A security boundary is one rule in one place | `packages/cli/resources/provider-boundary.json` holds one named clause vocabulary; `system-prompt.ts` and `rust-tui/src/boundary.rs` both render from it, and the crypto prohibitions are system text on both surfaces rather than user text on the CLI | `system-prompt.test.ts`, `boundary-drift.test.ts`, `boundary.rs`, `boundary_drift.rs` |
| §3.2 A task contract's role selects the prompt that runs it | `ROLE_PROFILES` and `profileForRole` in `packages/cli/src/system-prompt.ts` map every `AgentRole` to a `SystemProfile`, and the CLI's ask call site calls `profileForRole(options.role)` instead of naming a profile. `--role analyst` puts different bytes in the `system` field than no role does | `role.test.ts`; a mutation making `profileForRole` ignore its argument failed two named tests |

## 4. Findings

Severity is about impact on operator judgment, not exploitability of a machine.

### F1 — A verified hypothesis was promoted to strong evidence and to ELIGIBLE. **Fixed.**

`parseEvidenceRecord` permits `claimType: 'hypothesis'` with `verification: 'deterministic'`. `evaluateEligibility` tested only `verification`, so such a record alone made a case `eligible`, and `factorEvidenceQuality` mapped it to `high`. `bestEvidence` also sorted on `verification` alone, so a hypothesis could outrank a real fact on the same case.

This is the exact "hallucinated claim" failure the blueprint §12 lists, and the dossier would have presented the case as ready for owner review.

Fix, in `ranking.ts`: `confirmed` now requires `claimType === 'fact'`; `bestEvidence` sorts facts ahead of hypotheses; `factorEvidenceQuality` caps any hypothesis at `low`; `factorReproducibility` requires a fact. Covered by three tests in `ranking.test.ts` under "claim status is never inferred from verification alone".

### F2 — A block reason was reported twice. **Fixed.**

A case with neither a scope manifest nor a policy snapshot pushed `scope_absent` from two separate branches, so the dossier would have printed `blocked: scope_absent, scope_absent`. Cosmetic, but it misrepresents the gate. `evaluateEligibility` now de-duplicates.

### F3 — Untrusted strings are rendered into the operator's terminal unescaped. **Fixed.**

`renderDossier` interpolates `caseId`, `objective`, `claim`, `effect`, `receiptReference`, and factor `basis` values straight into markdown printed to a terminal. No C0 control characters, DEL, or escape sequences are stripped.

A hostile bundle can therefore rewrite the visible dossier, forge a second "All records link" section, or emit terminal escape sequences. Modern terminals are hardened against the worst of this, but the content-spoofing case does not need any escape sequence at all — a claim containing a newline and a fake `### case-… — ELIGIBLE` heading is enough.

**Fix.** `renderDossier` now routes every interpolated bundle string through `safe()`, which collapses line breaks to spaces and replaces C0, DEL, and C1 control characters with U+FFFD; table cells additionally go through `safeCell()`, which escapes `|`. Applied to case ids, objectives, assets, factor bases and references, claims, statements, assessments, approvals, outcomes, receipts, and provenance problems. Two tests pin it: a bundle whose objective carries an escape sequence and a newline renders with the escape replaced, the heading demoted to plain text on one line, and no line starting with the injected `## Injected`; a bundle whose assessment basis contains pipes renders every table row with exactly four cells, so untrusted text cannot forge a row.

### F4 — `decidedBy: 'human'` is an assertion, not an identity. **Fixed, with the limit stated as F15.**

The type makes a record that *says* an agent approved it unrepresentable in a way that reads correctly, but it proves nothing: anyone editing the bundle can type `"decidedBy": "human"`. Same for `recordedBy` and therefore for `disposition: 'paid'`.

**Fix, in two layers, because one layer would have been theatre.**

1. *The gate.* `ReviewReason` gained a seventh value, `confirmation_unsigned`. A matching confirmation now confers eligibility only when a signature over its payload verifies against a key the evaluator was handed; otherwise the case is held for review. `EvaluationOptions.confirmationSigned` **defaults to `false`**, so a bundle read straight off disk — with no store, no key set, no trust decision — can never reach `eligible`. This is the layer that matters, because the gate is what the operator acts on. `ranking.test.ts` covers all three states: signed and trusted, unsigned, and signed by a key nobody trusts.
2. *The store.* `putBundle` and `verifyStore` refuse any bundle in which an approval, outcome, confirmation, duplicate search, or assessment is unsigned, naming each record and pointing at `case sign`. This is why the dossier without `--store` reports a confirmed case as *awaiting a signature* rather than as queued.

The private key never enters a bundle or a store. `case sign --key FILE` reads an operator-supplied ed25519 PKCS#8 PEM, signs in memory, and writes only the signed JSON to stdout; the store's `manifest.json` holds a `publicKeySpkiDerBase64` and nothing else. A test walks every byte in a populated store and asserts none of them contains a line of the private key. What a signature still cannot tell you is F15.

### F5 — Digests are declared, never recomputed. **Fixed for local bytes; the residual is F16.**

`contentDigest` and `payloadDigest` were validated for *shape* (`sha256:` plus 64 lowercase hex) only. Nothing in this slice hashed any content, so a bundle could claim a digest for material that does not exist or does not match.

**Fix.** `checkSourceDigests` resolves every `SourceRecord` whose `uri` is `file://` or `local://` against a base directory, hashes the bytes, and compares them with the declared digest. A mismatch refuses the `put` and names the source, the URI, and *both* digests; a declared local source whose bytes are absent refuses too. `getBundle` re-checks on every read and `verifyStore` re-checks across the whole store, so editing a stored bundle or a local file after the fact is caught rather than trusted. A digest is still a shape guard until the store hashes something, and that is now the store.

What a local recomputation cannot establish is F16.

### F6 — `writablePaths` and `capability` are declarative only. **Fixed at parse time; the limit is F17.**

A task could declare `writablePaths: ['../../etc/passwd']` with `capability: 'modify'` and parse successfully.

**Fix.** `path-guard.ts` holds the lexical path rules that used to live privately inside `patch.ts` — `withinRoot`, `isSensitivePath`, and the string-level half of `assertSafePath` — and `patch.ts` now imports them, so the patch path and the declared path cannot drift apart. `parseTaskContract` runs `assertDeclarablePath` over every `writablePaths` entry, after the capability check and before the record is returned, so a traversal, an absolute path, a quote or backslash, a `.git` segment, or a `.ssh`/`secrets`/`credentials`/`.env*`/`.pem`/`.key`/`.p12`/`.pfx` path **fails to parse**.

**The limit this does not cover, stated plainly.** The parser is synchronous and pure; it cannot `lstat` or `realpath` anything. So a symlinked parent directory inside the workspace still parses successfully — the segment walk that catches that lives in `assertSafePath`, which runs later, at patch-apply time. Beyond the symlink, there is no executor and no OS isolation in this slice at all: the guard is enforcement-at-parse. It constrains what a contract is allowed to *say*, and nothing yet consumes what it says. F17 carries this forward as the binding constraint on the Engineer adapter.

### F7 — One malformed asset aborts the whole dossier. **Fixed.**

`isTargetInScope` throws on an unparsable target, and `rankCandidates` does not catch it, so a single case with `assetId: 'not-a-url'` fails the entire command with a non-zero exit. This fails closed, which is the right direction, but it denies the operator the other cases rather than blocking one.

**Fix, in two parts.** The root cause is removed structurally: `CaseRecord.asset` is now a discriminated `AssetIdentity` derived by `normalizeAsset(assetOriginal)`, and only an `exact` identity is ever passed to `isTargetInScope`. A non-URL, a wildcard, or a value carrying a query can no longer reach the scope check at all, so the throw is unreachable from a parsed bundle. As a backstop, `rankCandidates` now catches per case and emits `eligibility: 'not_evaluated'` with the reason on the vector, which the dossier prints as `NOT EVALUATED` and keeps out of the actionable queue. The state is a distinct `Eligibility` value rather than a fabricated block reason, because a failure to evaluate is not a fact about the case.

### F8 — `authorization_unknown` is reserved and unemittable. **By design; binding on later phases.**

The `BlockReason` union includes it, and nothing in this slice can produce it, because the schema has no concept of a granted authorization. Any future adapter that fetches a remote source **must** emit it before it fetches, not after. Recorded here so a later phase cannot quietly delete the variant as unused.

### F9 — Record ids share one global namespace. **By design; do not "fix".**

`validateCaseBundle` collects ids from all six record types into a single duplicate check, so a case id equal to a source id is reported as a duplicate. This is intentional: cross-type id confusion should fail closed. A future per-type store must preserve the check rather than namespace the ids to make it pass.

### F10 — Retention classes record an intention, not an enforcement. **Fixed, with the limit stated as F21.**

Every source must name a retention class, which is the right pressure. What was missing is anything acting on it. `retentionReport` and `purgeExpired` in `packages/cli/src/store.ts` now compute each stored source's age against its class and delete what is past its window, exposed as `terminal221b case store retention`. Three restraints, each one deliberate:

- **The report never guesses a window.** How long outcome data may be kept was open decision 3 and is now answered (7 / 180 / 180 days, archive never), but the answer lives in `DEFAULT_RETENTION_POLICY` and reaches the store only through a policy file the operator records with `--record-default-policy`; `retentionReport` takes its windows as an argument and applies none of its own. The rule that survives the decision is that a class with no window reports `unconfigured` and is *not* treated as safe to delete, because silently expiring what nobody decided the retention of is the tool inventing a policy.
- **A purge removes a whole revision, never a single record.** A bundle's signature covers the whole bundle, so dropping one source out of the middle would rewrite signed bytes and silently invalidate every attestation in the file. Deleting a revision removes the evidence without falsifying any signature.
- **A purge cannot be blind.** The report prints a token derived from the purgeable set; `purgeExpired` recomputes it and refuses a mismatch, so a store that changed in between cannot be purged against a decision the operator never made.

Age is measured from `observedAt`, which the operator records, so the number describes the operator's record-keeping and not the source. `operator_archive` has no window at all, because the operator already chose to keep it. The residual is F21.

### F11 — The actionable queue was reachable with no human in the loop. **Fixed. High.**

`evaluateEligibility` granted `eligible` on a deterministic evidence record alone. The design defines ELIGIBLE as the exact asset and the current policy both *confirmed*, and the workflow calls for operator confirmation before a case becomes actionable. With no confirmation record in the schema, a bundle of machine-written records could populate the queue on its own, and scope drift is named as a top risk in the design.

**Fix.** A `ConfirmationRecord` is now required, and it is pinned: it carries both `asset` and `policySnapshotId`, and eligibility requires a confirmation whose pair matches the case's own pair. A confirmation recorded against last year's snapshot, or against a different repository, no longer confers eligibility — the case reports `confirmation_mismatch` instead. The pin is the reason this is a new record type rather than an `ApprovalRecord` with a free-text `effect`, which could not carry it. Tests: a fully evidenced in-scope lead with no confirmation is held; a confirmation pinned to another asset is unusable; a confirmation pinned to the stale snapshot is a mismatch.

### F12 — Asset identity was a single string with no recorded original. **Fixed. High.**

`CaseRecord.assetId` had to already parse as an absolute HTTPS URL, so nothing recorded what the intake source actually said, nothing detected a wildcard or an ambiguous value, and a near-miss name like `checkout-service-legacy` was indistinguishable from a deliberate one.

**Fix.** The bundle now records `assetOriginal` and `assetType`; `asset` is *derived* by `parseCaseRecord` and is rejected as an unknown field if supplied, so the identity cannot be forged independently of the text it came from. `normalizeAsset` in `packages/cli/src/scope.ts` never widens to a prefix, never drops a query, fragment, or credential, and never guesses a TLD; anything it cannot reduce to one exact HTTPS asset comes back `wildcard` or `ambiguous`, and only an `exact` identity can reach the scope gate. A wildcard or ambiguous asset is held for review, never blocked and never queued. Ten tests cover the reduction rules, including one that normalization never turns a non-match into a match and one that it never widens an exclusion.

A defect was found while writing those tests: the URL parser silently drops a trailing `?`, so `https://example.invalid/programs/checkout-?` was reducing to `https://example.invalid/programs/checkout-` — a shorter asset than the operator wrote, in exactly the direction the function promises never to go. `?` and `#` are now rejected before parsing.

### F13 — A missing policy snapshot was reported as a missing scope. **Fixed. Medium.**

A case whose `policySnapshotId` did not resolve pushed `scope_absent`, which is a different and much broader problem: it told the operator their program manifest was missing when the real fault was one dangling source reference. Fixed by a distinct `policy_snapshot_missing` reason.

### F14 — Freshness and the version string were both weaker than the factor implied. **Fixed. Medium, with a limit stated.**

`freshness` was derived from an operator-recorded `observedAt` and nothing else, and read as though the policy were known to be current. `policyVersion` was parsed and never read, so a snapshot edited behind an unchanged version label was invisible.

**Fix.** Every freshness basis now states that `observedAt` is operator-recorded and not corroborated, the dossier says so in its header and its closing list, and `policyVersionProblems` reports two snapshots that share a version string but differ in content. Version strings are deliberately not *ordered* — no rule in this code should claim to know that `2026-09` postdates `2025-01`, and formats like `v3.10` versus `v3.9` would make a lexicographic answer confidently wrong. Deciding which contradicting snapshot is current stays a human act.

The limit that remains is stated in full in [FRESHNESS-REVIEW.md](./TERMINAL221B-FRESHNESS-REVIEW.md): the digest is shape-checked and never recomputed, so `freshness: high` is a statement about the operator's record-keeping, not about the policy. A future `observedAt` is not rejected, so a bundle can claim a snapshot is newer than the evaluation date and pass. F16 narrows the first half of that limit and not the second.

### F15 — A signature proves a key holder signed the bytes, not which person did. **Open by design. Low. Binding on later phases.**

The F4 fix makes a human act attributable to a *key*. It does not make it attributable to a *person*: anyone who can read the private key file can produce a signature the store accepts, and a shared key produces a signature that names nobody in particular. The signature also says nothing about *when* the human decided — `signedAt` is chosen by the caller, so a signature can be dated after the fact with no independent witness.

This is stated rather than fixed because the fix is a key-management policy, not code: per-human keys, a key roster the operator reviews, and for anything load-bearing a second signature. The code's obligation is to not overstate what it has, which it now does not: the dossier's closing list says a signature proves who held the key, not which person typed it.

**That obligation was enforced where it was weakest (2026-10-02).** The caveat lived only in that closing list, so a confirmation row read `signed=yes` in the screen's detail pane — a reading the field cannot support, because it records that a record carries an attestation and not that the attestation verifies. The row now says `attested`, and the test asserts both halves: the honest word present, `signed=` absent. Verification remains the gate's answer and is reported in the header, which is where it already was. The finding stays open, because renaming a field does not make a shared key name a person.

### F16 — A recomputed digest covers local bytes only. **Open. Low, and it cannot be closed offline.**

`checkSourceDigests` resolves a source to a path and hashes the bytes at that path. That is a real integrity check for anything on this machine, and it is the whole of what it is. Three sources in the shipped fixture fall outside it: an `https://` URI is never fetched (no code path in this slice performs egress, and F8's `authorization_unknown` exists for the phase that would), and a `file://` URI *naming a host* — `file://reports/x.json` — is a remote file, not a local one, so it is recorded `unverifiable-here` rather than guessed at.

A declared digest on such a source is therefore still a shape-checked assertion. The store reports those sources as `unverifiable-here` in every `put`, `get`, and `verify` rather than counting them as verified, so an operator reading the summary can see the difference. A future adapter that fetches a remote source must recompute the digest at fetch time and must emit `authorization_unknown` *before* the fetch, not after.

### F17 — The path guard was enforcement-at-parse, with no executor and no OS isolation. **Fixed 2026-10-02. Was: low today, high the day something acted on a contract.**

F6 fixed the parse-time tier: a contract that declares a traversal, an absolute path, a `.git` segment, or a sensitive file cannot be constructed. Two gaps remained and neither was closable by adding a check to the parser.

*The symlink gap.* The parser is synchronous and pure, so it cannot `lstat` a path. A `writablePaths` entry that is lexically clean but whose parent directory is a symlink out of the workspace still parsed. The segment walk in `assertSafePath` caught that at patch-apply time; between parse and apply there was a window in which the declaration was not the truth.

*The executor gap, which was the larger one.* No code opened a path from a task contract. The guard constrained what a contract *said*; it granted nothing. The day an Engineer adapter read `writablePaths` as a permission, validation alone stopped being the boundary.

**Fix.** `packages/cli/src/executor.ts` exists, and it closes both gaps by acting rather than by checking.

Landing a candidate diff is a separate command, `case task apply`, gated on an `ApprovalRecord` whose `payloadDigest` is the digest of the exact bytes read back from disk and whose attestation verifies against a key a case store trusts. With no store, `readManifest` throws and nothing is applied. The model never writes: it returns a diff, and `acceptanceChecks` are operator-declared commands the executor runs.

The symlink window is closed by running the segment walk *before* a permission is used, twice: once against the operator's workspace and once against the task worktree the sandbox will actually write to, since those are two different filesystems. A lexically clean `writablePaths` entry whose parent is a symlink out of the workspace now refuses before a bind mount exists, and the run is reported `blocked` rather than attempted.

The executor gap is closed by `bwrapSandbox`, which binds `/` **read-only** so the only writable locations in the sandbox are explicit `--bind` mounts built from the resolved write set, and which drops the network namespace so the Research rung of the ladder is off by construction. A write outside the declared set is refused by the kernel rather than by a function. `resolveSandbox` **throws when bubblewrap is absent** rather than falling back, because a silent fallback would have reintroduced this finding while still reporting success; the one way out is the named `--allow-unsandboxed` opt-in, which sets `isolated: false` in the report and writes a `finding` event saying the write set was not enforced.

**The kernel's granularity, stated plainly.** The sandbox mounts **directories**, never files — binding a single file makes it a mount point, and `git apply` unlinks before it rewrites, so a file bind fails `EBUSY` on any patch that touches a file that already exists. So `writablePaths: ['src/app.txt']` mounts `src/`, and the kernel's write set for that task is one directory, not one file. The exact declared set is enforced by the *other* layer, `pathsOutsideWritable` on the diff's changed paths, which is TypeScript rather than the filesystem. The two compose and neither is precise alone; describing the sandbox alone as enforcing the declared set would be false.

**What this does not make true.** The isolation is Linux-and-bubblewrap only; the operator may still pass `--allow-unsandboxed`, and the report says so. `applyTaskDiff` binds the whole workspace read-write when it applies, so `git` itself is trusted with the write — it is constrained by the already-verified path set, not by the sandbox. A task still cannot merge, push, or sign. **F17 is closed for the write path; it is not a claim that the whole surface is contained.**

**How this was found, because the method matters.** The unit tests passed and two of them were genuinely negative controls, yet `case task apply` failed end to end with `EBUSY`. The file bind was only found by running the built CLI against a scratch repository: the tests injected a fake sandbox, and no test performed a real `git apply` through a real mount. The regression test `lands a git apply onto an existing file, which a file bind cannot` now exists, against real `bwrap`.

### F18 — A `CaseBundle` was not JSON-round-trippable, so the store could not read back its own writes. **Fixed. Medium, found by the store rather than by a test.**

`parseCaseRecord` derived `asset: normalizeAsset(assetOriginal)` and F12 deliberately excluded `asset` from the record's known-field list so the identity could not be forged independently of the text. That is correct for a hand-written bundle and fatal for a stored one: `putBundle` serialises the parsed bundle, `getBundle` re-parses it, and the re-parse threw `Case record has an unknown field asset` for all eleven fixture cases. Proven before the code was changed, with a scratch round-trip script rather than a guess.

**Fix.** `asset` is now an accepted field. When present it must equal the identity derived from `assetOriginal`, checked by a new `sameIdentity` helper; when absent it is still derived. So the forged-identity hole F12 closed stays closed, and a stored bundle survives a store round trip. What this cost is stated here rather than buried: a derived field that the parser emits is no longer a field the parser can treat as unknown, and every derived field in the other eleven record types deserves the same treatment before a store ever depends on it.

### F19 — The store's integrity check compared a digest with itself. **Fixed. High, and the reason it is high is the shape of the bug.**

`listEntries` computed each entry's `bundleDigest` by hashing the file it was about to check, and `verifyStore` then compared that value against itself. The comparison could not fail. A test that tampered with a stored bundle appeared to pass only because it also tripped an unrelated object-store check — which is exactly how a tautological check survives a green suite.

**Fix.** The digest that vouches for a revision is the one recorded in `transitions.jsonl` when the revision was written. `StoreEntry.bundleDigest` is now optional and read from that log, never from the bytes under test, and `verifyStore` reports a revision with no recorded digest as *nothing vouching for these bytes* rather than passing it. The general lesson belongs in every future check: a digest derived from the artefact under test is not a check.

### F20 — The store was keyed per case, but a bundle carries one scope and one policy snapshot for all its cases. **Fixed. Medium.**

The first store implementation filed one entry per case and refused a bundle that carried more than one, which the shipped fixture does — eleven. The obvious repair, splitting a bundle per case, would have been the wrong design rather than an inconvenient one: a bundle exists to bind one scope manifest to one policy snapshot across its cases, and splitting would let a later revision change the snapshot while an earlier case's records stayed behind, which is precisely the split the scope gate exists to prevent.

**Fix.** The store is keyed by **bundle**, filed under the first case's id by default, with `entryName` validating any explicit name against `/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/` and rejecting `..` before the name ever becomes a path. A hostile `--entry ../../escape` is refused by name, not sanitised into a different path.

### F21 — A purge can only remove a revision, never the oldest content inside a live one. **Open by design. Low.**

The newest revision of every entry is never purgeable, so a store always keeps something current. The consequence is that a long-lived entry accumulates revisions and the content inside the newest one is never removable, even once every source in it is years past its window. Closing it means writing a new revision with the stale sources removed, which is a signed operation: the bundle must be re-signed and re-put, and the old revision is then purgeable. That is a deliberate two-step with a human signature in the middle, not an omission. It is binding on Phase 5, where outcome records are retained and then expire.
### F22 — A security boundary enforced in two places had already drifted. **Fixed, with the limit stated as F23.**

The crypto prohibitions were a **system prompt** in the Rust TUI and **user text** in the CLI, because `cli.ts` passed them through `buildCryptoPrompt` into the prompt while `anthropic.ts` sent its own hardcoded coding-assistant string as `system`. The CLI was therefore running the weaker copy of a boundary, and the copy anyone invoking `terminal221b crypto ask` actually received. The two non-crypto system strings also disagreed on wording. Three provider implementations existed, each with its own error handling, its own system prompt, and no shared test.

The fix is one clause vocabulary. `packages/cli/resources/provider-boundary.json` is the single source of truth; `packages/cli/src/system-prompt.ts` and `packages/rust-tui/src/boundary.rs` both render from it, so a clause cannot exist on one side and be missing on the other. `AGENTIC-ENGINEERING.md:213-231` maps one-to-one onto clause names, so a profile is auditable by reading a list of names.

The guard is proven in both directions rather than asserted: `packages/cli/tests/boundary-drift.test.ts` and `packages/rust-tui/src/boundary_drift.rs` each mutate a copy of the real file with a prohibition removed and assert the renderer notices, and each carries a control that asserts the unmutated file still has it. A guard that has only ever run green has not been shown to fire. The residual is F23.

### F23 — The shared boundary is a convention held by two readers of one file, not a schema check. **Open by design. Low.**

Nothing verifies at build time that the two clause vocabularies are identical; each side asserts against the shared file independently, so a clause added to only the TypeScript enum is caught by the next test run rather than at compile time, and only if someone remembers to run the other suite. Closing it means a generated vocabulary — one file the compiler reads on both sides — which requires a build step this repository does not have. The cost of not closing it is a drifted clause caught by a test rather than a compiler, which is the right trade for a repository with no codegen. The Expo app is the third surface; it shares the failure vocabulary by type-only import, but its renderer is a duplicate for the reason in F25.

**A second instance of this shape was found and closed (2026-10-02).** The dossier's operator question was a Rust constant at `packages/rust-tui/src/dossier.rs:26` while the markdown export at `packages/cli/src/dossier.ts` had no equivalent — so the export answered a question it never stated. That is this finding exactly, in a different boundary. It is now carried as `operatorQuestion` in the report payload beside `notDoing`, which is the same shared-data remedy already used for the clause set, and `dossier.test.ts` fails if the Rust side grows a constant of its own. The report version moved 1 to 2 so the field could be required: serde parses the whole struct before a version check runs, so a required field on a v1 report would surface as a serde missing-field error an operator cannot act on. `parse_report` therefore reads `version` from the raw JSON first, and a v1 report produces the actionable "the CLI sent version 1, rebuild it" instead.

This finding stays **open for the clause vocabulary itself** — that one still needs codegen, and is unchanged.

### F24 — The Expo app had its own provider implementation, with no timeout and a catch-all. **Fixed. Medium, with the residual stated as F25.**

`src/services/api/ClaudeService.ts` sent to the same endpoint with the same version header and **no timeout at all**, and collapsed every failure into one string, which is exactly what blueprint §6.4 forbids. Both halves are fixed:

- **The timeout.** `timeoutSignal()` builds an `AbortController` and a `clearTimeout`-cancelled timer by hand, and the `signal` goes on the request. `AbortSignal.timeout` was not used because it does not exist in every React Native runtime this app may ship to, and an uncancellable request is the thing this finding is about. The old code had no way to cancel a request at all.
- **The collapse.** The transport `catch` now produces a typed `ProviderFailure` — `timeout` when the signal fired, `network` with the cause otherwise — and a non-`Error` throw is typed rather than discarded. An unparseable error body keeps its HTTP status instead of vanishing. A success body that is not JSON is `invalid_json`, not `no_text_block`. **A whitespace-only text block is a refusal, never an empty success**, which the old code returned as `''` and the caller rendered as a blank assistant turn.
- **The vocabulary is shared, not copied.** `ClaudeService.ts` imports `ProviderFailure` from `packages/cli/src/provider.js` **as a type only**, so the three surfaces cannot drift on the failure union — the compiler enforces it. `validateApiKey` now returns the typed failure rather than a bare `false`, because a boolean is the same collapse this finding is about: a wrong key and a network outage are different problems with different fixes.

Both halves are proven to be caught, by mutation rather than by assertion: reintroducing the missing `signal` fails 2 tests, and reinstating the catch-all fails 3, including "a timeout is a timeout". A control test reads the source and fails if either is removed, so the guard cannot go quietly green.

### F25 — The Expo surface shares the failure *type* but not the failure *renderer*. **Open by design. Low.**

`describeClaudeFailure` duplicates `describeFailure` from `packages/cli/src/provider.ts`, and `CLAUDE_SERVICE_TIMEOUT_MS` duplicates `DEFAULT_TIMEOUT_MS` from `packages/cli/src/anthropic.ts`. The duplication is forced: the CLI's renderer reaches a JSON file through `node:fs`, and a *value* import of it would drag that into the React Native bundle, which fails at runtime rather than at build. The type import is safe because it is erased. So the failure *vocabulary* is enforced by the compiler and the two *rendered strings* and one *number* are held by convention. A test asserts the two timeout constants still agree, which is the only thing making the duplicated number safe to carry. Closing this means a build step or a runtime-loaded boundary, neither of which this repository has; it is the same shape as F23 and the same trade.

### F26 — A role selects a system profile, and four of the five roles are still labels. **Fixed, with the residual written down.**

`TaskContract.role` was parsed, stored, and never read by anything that shaped a prompt. A role was a string in a JSON file, so "this is the analyst role" was an assertion with no consequence: `terminal221b ask --role analyst` did not exist, and `crypto ask` vs `ask` chose between two hardcoded profile names at one call site. A profile that nothing can select is a prompt nobody runs.

The fix adds a third profile to the one clause file, `analyst`, and makes the role the parameter that selects it: `ROLE_PROFILES` in `packages/cli/src/system-prompt.ts` is a total `Record<AgentRole, SystemProfile>`, `profileForRole(role)` is what the CLI's ask call site now calls, and `--role` is how a user supplies one. An ask with no `--role` resolves to `'coding'`, which is the profile it resolved to before the table existed.

What this does **not** fix is that four of the five roles still map to `'coding'`. `scout`, `engineer`, `artist` and `reviewer` remain labels, and `ROLE_PROFILES` makes that explicit rather than accidental — each is a named entry saying "this role runs the coding profile", so adding a profile for one of them is a one-line change with a diff that says what it means. A role that maps to coding is not wrong; it is unfinished, and the table is where the next one goes.

Two things this slice deliberately does not do. It does not accept `--role` on `crypto ask`: two profiles would apply and the quiet resolution loses one of them, so it refuses. And it duplicates the role vocabulary from `case.ts` rather than importing it, because `AGENT_ROLES` is not exported there and `case.ts` is outside this slice's write scope — the duplication is pinned by a test that reads the parser's own enumeration, so the two lists cannot drift silently. That duplication is F27's shape.

## 5. What this review does not claim

- That the dossier is safe to render for an arbitrary third-party bundle. It now strips control characters and escapes table cells (F3), but the review has not been repeated against a hostile bundle authored by a third party rather than by this review's own tests.
- That approvals, outcomes, or digests are trustworthy. They are now signed and, for local sources, recomputed — but a signature names a key rather than a person (F15) and a local digest cannot speak for a remote source (F16).
- That a human confirmed anything. `confirmedBy: 'human'` is still a typed assertion, and now sits directly under a signature: a case is queued only when that assertion is signed by a key the store trusts, and the key is trusted because an operator registered it. Attributing a signature to a named person is F15, and it is not done.

### F27 — The role vocabulary is duplicated between `case.ts` and `system-prompt.ts`. **Open by design. Low.**

`AGENT_ROLES` in `packages/cli/src/case.ts:37` is not exported, and `system-prompt.ts` needs the same five names to validate `--role` and to key `ROLE_PROFILES`. The slice therefore owns a second literal list. This is F23's shape in a smaller package: a rule in two places, held by a test rather than by the compiler. `role.test.ts` reads the parser's own error string — `role must be one of: scout, analyst, engineer, artist, reviewer` — and asserts it equals the joined list, so a role added to one side without the other fails the suite. The exposure is bounded: a duplicate of five strings whose only consumer is a lookup table, where a mismatch produces a test failure rather than a wrong prompt. Closing it means exporting `AGENT_ROLES`, which is a one-line change to a file that was deliberately out of this slice's scope.
- That the path guard keeps a write inside the workspace. It keeps a *declaration* legal. The executor now opens those paths, and the write set is enforced by bubblewrap with `/` read-only — but only when bubblewrap is present, and `--allow-unsandboxed` turns that off deliberately (F17).
- That a role does anything an operator can rely on, except for `analyst`. Four of five roles still select the coding profile (F26), and the role vocabulary is duplicated rather than shared (F27). Selecting a profile is not performing the role: nothing schedules, scopes, or audits an ask by role yet.
- That the ranking predicts impact, reward, or payout. It has no numeric aggregate and no outcome data. Two of its seven factors are now derivable or assessed (`novelty`, `effort`); `impact_fit` and `reward_fit` are settable only by an assessment that cites the program record, and remain `unknown` otherwise.
- That an agent can reach a target. Nothing in a task run opens a socket: the sandbox drops the network namespace, and `resolveSandbox` refuses to run without it. That is a Linux-with-bubblewrap property, not a property of the schema.
- That any agent exists. The `role` field is a label on a contract. No orchestration or scheduler is implemented; the executor runs one contract the operator hands it.
- That Phase 2 or later inherits any of this safety. A Textual prototype, a source adapter, or an Engineer adapter each need their own review; the boundaries here are a floor, not a grant.

## 6. Gate result

The Phase 0 gate reads "schema tests, provenance invariants, threat-model review". All three are satisfied: `case.test.ts` (49 tests) covers the contracts and the reduction rules, and the provenance and property tests in `ranking.test.ts` (53 tests) cover the gate. This document is the third, and it closes with eight findings fixed in code (F1, F2, F3, F7, F11, F12, F13, F14) and F4, F5, and F6 recorded as open with their required fixes, so that the next phase inherits a written list rather than a false impression of safety.

This document was re-reviewed after the Phase 1 gate work. The second pass found F11 to F14, three of them high or medium, and they are fixed in the same commit-less working tree as the gate they belong to.

The third pass re-ran the same gate after the case store landed and found F4, F5, and F6 fixed, and found three more defects in the process of closing them: F18 (a bundle was not JSON-round-trippable), F19 (an integrity check that compared a digest with itself), and F20 (the wrong storage unit). All three were found by running the store, not by reading the store.

### The gate, re-run, with the output actually seen

The gate reads **schema tests, provenance invariants, threat-model review**. Each is answered below with the command that produced it, in the working tree as it stands.

**1. Schema tests — PASS.**

```
$ npx vitest run
 Test Files  14 passed (14)
      Tests  229 passed (229)
```

`case.test.ts` (49) still covers the contracts, the reduction rules, and the unknown-field rejection; `path-guard.test.ts` (20) covers the extracted path rules and the `parseTaskContract` guard; `store.test.ts` (67) covers canonicalisation, signing, verification, digest recomputation, and the store lifecycle.

**2. Provenance invariants — PASS.** The invariant suite is the `property invariants` block in `ranking.test.ts`, and it now includes `a confirmation for a different snapshot never confers eligibility` alongside the pre-existing monotonicity and normalisation properties. Run as a group:

```
$ npx vitest run packages/cli/tests/case.test.ts packages/cli/tests/ranking.test.ts \
    packages/cli/tests/store.test.ts packages/cli/tests/path-guard.test.ts
 Test Files  4 passed (4)
      Tests  211 passed (211)
```

Within that, the four cases under `a case reaches the queue only through human confirmation` are the gate the store exists to close, and the three under `the eligibility gate reads the store trust decision` in `store.test.ts` are the same property seen from the store's side.

**3. Threat-model review — PASS, with the residuals written down.** This document is that review. It closes with **eighteen** findings fixed in code (F1, F2, F3, F4, F5, F6, F7, F10, F11, F12, F13, F14, F18, F19, F20, F22, F24, F26), and F15, F16, F17, F21, F23, F25, and F27 recorded as open with the limits they carry with the limits they carry, so that the next phase inherits a written list rather than a false impression of safety. F8 and F9 remain by design and are binding on later phases.

### What the gate does not cover, restated as a limit on the next phase

The three gate items were satisfied by a **pure, offline reader, a renderer, and a local store**. None of them is an executor. A contract can still declare a task, nothing will run it, and no isolation exists around whatever will one day run it. F17 is the finding that says so, and it is the reason the Engineer adapter needs its own review rather than inheriting this one.

