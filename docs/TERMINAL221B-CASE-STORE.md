# Terminal221b local case store

**Status:** shipped in the working tree, uncommitted.
**Date:** 2026-09-30.
**Scope:** `packages/cli/src/store.ts`, `packages/cli/src/path-guard.ts`, the `case store` and `case sign` verbs in `packages/cli/src/cli.ts`, and the `attestation` field added to the five human-authored records in `case.ts`.
**Threat model:** [CASE-THREAT-MODEL.md](./TERMINAL221B-CASE-THREAT-MODEL.md) — this store is what closed F4, F5, and F6, and finding it is what turned up F18, F19, and F20.
**Blueprint:** §10 of [TERMINAL221B-SYSTEM-ARCHITECTURE.md](./TERMINAL221B-SYSTEM-ARCHITECTURE.md).

## 1. What this is

A local, offline directory that holds case bundles, refuses a bundle it cannot vouch for, and gives the eligibility gate a trust decision it did not have before.

```bash
terminal221b case store init   --store ~/.local/share/terminal221b \
                               --public-key operator.pub --key-id operator-key
terminal221b case sign  bundle.json --key operator.pem --key-id operator-key > signed.json
terminal221b case store put  signed.json --store ~/.local/share/terminal221b --base-dir .
terminal221b case store get  case-exact-in-scope --store ~/.local/share/terminal221b
terminal221b case store verify --store ~/.local/share/terminal221b
```

Three properties it has, and one it does not.

- **A human act is signed, not typed.** `decidedBy: 'human'` was always writable by anything that can edit the bundle (F4). Each of the five human-authored records now carries a detached ed25519 `attestation`, and the store refuses the bundle if any one of them is unsigned.
- **A digest is computed, not believed.** `contentDigest` was a shape check (F5). The store now hashes the local bytes of every `file://` and `local://` source and refuses the put if they disagree.
- **A stored bundle is the bundle that was signed.** Every `put` is re-verified on read, and every `verify` re-hashes each revision against the digest recorded in the transition log when that revision was written.
- **It does not enforce retention.** `retention` on a source is still a label. F10 stays open, and Phase 1 stays *partially done* for that reason.

## 2. Layout

```
<store root>/
  manifest.json             format version and a frozen base list of trusted keys
  keys/<sha256(keyId)>.json one file per trusted key, created exclusively
  transitions.d/*.jsonl     append-only, one log per writer process: init, trust, put, purge
  transitions.jsonl         legacy shared log from older stores; read if present, never written
  bundles/<entry>/<n>.json  one file per revision
  bundles/.format-v2        a regular file that makes older CLIs fail loudly
  objects/<sha256-hex>      content-addressed copy of each stored bundle
```

There is no lock. Writers claim names with an exclusive create and retry on a collision; see `docs/adr/0001-lock-free-case-store.md`. Temp files (`.<name>.tmp-<hex>`) and condemned objects (`objects/.condemned-*`) are ignored by readers and listed by `verify` if an interrupted write left them; an entry whose name merely contains `.tmp-` is not one.

Upgrading a version 1 store (done by `init`, or by the first `put`, `trust` or `retention --purge` that meets one) is refused while an older `terminal221b` holds `<store>/.lock` with a live pid, and says so; let it finish or remove the lock. Migration copies every v1 key into `keys/` and retries if the manifest changes underneath it. Version 1 binaries are then locked out of `put`, `trust`, `verify`, `get`, `list` and the retention report and purge. They are **not** locked out of `retention --record-default-policy` (it can still replace `retention.json`) or of `init`, and an old command that was already running when the store was upgraded is not stopped; see the ADR for exactly what that can and cannot touch.

The store root comes from `--store`, else `$XDG_DATA_HOME/terminal221b`, else `~/.local/share/terminal221b`. It is deliberately **outside any repository**: `case store init` says so on every run, because a store inside a git tree is a store whose attestations and operator key ids end up in a commit.

### Why an entry is a bundle, not a case

`bundles/<entry>/<n>.json` is keyed by **bundle**, filed under the first case's id by default. This is F20, and it is worth stating because the obvious design is wrong: a bundle binds one scope manifest and one policy snapshot across all its cases. Splitting per case would let a later revision change the snapshot while an earlier case's records stayed behind — exactly the split the scope gate exists to prevent. `--entry NAME` overrides the name, and `entryName` validates it against `/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/` and rejects `..` before the name ever becomes a path segment.

## 3. Signing

`case sign` reads an operator-supplied ed25519 PKCS#8 PEM, signs in memory, and writes the signed JSON to stdout. **The private key is never copied, logged, or written into the bundle or the store.** `store.test.ts` walks every byte under a populated store root and asserts that none of them contains a line of the private key; the end-to-end script repeats the check with `grep -r "PRIVATE KEY"` over the store.

The store holds the public half only, as `publicKeySpkiDerBase64` in `keys/<sha256(keyId)>.json` (and in the manifest's frozen list for stores created before keys/ existed):

```json
{
  "version": 1,
  "trustedKeys": [
    {
      "keyId": "operator-key",
      "publicKeySpkiDerBase64": "MCowBQYDK2VwAyE...",
      "addedAt": "2026-09-30T12:00:00Z"
    }
  ]
}
```

Registering the same `keyId` twice is refused. Trust is widened by an explicit act that shows up in `transitions.jsonl`.

### What is signed

Five record kinds: `approval`, `outcome`, `confirmation`, `duplicateSearch`, `assessment`. These are exactly the records with a `decidedBy` / `recordedBy` / `confirmedBy` / `performedBy` / `assessedBy` field typed the literal `'human'`. The shipped fixture has eleven such records and all eleven are signed by `case sign`.

### The exact bytes

The signature input is exactly this, UTF-8, with one trailing newline:

```
terminal221b/record-signature/v1\n<recordKind>\n<recordId>\n<payloadDigest>\n
```

and `payloadDigest` is `sha256:` + hex(sha256) of the **canonical JSON** of the record with the `attestation` key removed. Canonical JSON means: object keys sorted ascending, no whitespace, array order preserved (array order is meaning), `undefined` omitted, non-finite numbers refused.

Four consequences, each with a test:

- The `attestation` is excluded from its own payload, so signing is not self-referential and re-signing a record cannot loop.
- `recordKind` and `recordId` are newline-framed, so an id cannot smuggle a different kind/id pair across the boundary.
- A valid signature does not transplant onto another record id or another record kind.
- `payloadDigest` is the same name `ApprovalRecord` already used, and means the same thing: a digest over the record's payload.

`verifyRecord` returns one of five statuses — `signed`, `unsigned`, `unknown-key`, `bad-signature`, `digest-mismatch` — and checks the digest *before* the signature, so an edited payload reports `digest-mismatch` rather than a signature failure.

## 4. What the store checks, and in what order

`putBundle` runs these in order and writes nothing until all of them pass:

1. `validateCaseBundle` — every provenance link resolves.
2. Signatures — every human record is `signed` under a trusted key. A refusal names every offending record and points at `case sign`.
3. Source digests — every reachable local source's bytes hash to its declared `contentDigest`. A refusal names the source, the URI, and **both** digests.

Then, with no lock: the bundle is serialised, a copy written to `objects/<sha256>`, the next revision claimed exclusively as `bundles/<entry>/<n>.json` (a collision re-lists and takes the next number), its digest recorded in this process's `transitions.d/` log, and the object re-checked. A read without `--revision` returns the newest revision a transition vouches for.

`getBundle` re-runs all of it on the way out, including for an explicit `--revision`: a revision no put transition vouches for, or whose bytes no longer hash to the digest the put recorded, is refused (or listed as a problem with `--no-verify`). `verifyStore` re-runs it across every revision in the store and additionally compares each file's bytes against the digest recorded at write time — never against a digest recomputed from those same bytes, which is F19 and the reason a green suite did not catch it.

## 5. Source verification reach

| Source `uri` | Treated as | Result |
|---|---|---|
| `local://path` | resolved against `--base-dir` (default: cwd) | `verified`, or refused on mismatch, or refused if absent |
| `file:///abs/path` | an absolute local path | `verified` |
| `file://host/path` | a **remote** file, not a local one | `unverifiable-here` |
| `https://…` | remote | `unverifiable-here`, **never fetched** |

`local://` with a `..` segment is refused outright rather than resolved. An `unverifiable-here` source still has to carry a shape-valid digest, but that digest is an assertion — see F16. Every `put`, `get`, and `verify` prints the split, e.g. `2 source(s) verified locally, 3 unverifiable here`, so an operator never has to guess which number they are reading.

## 6. How the gate uses it

`evaluateEligibility` gained one optional member, fail-closed by design:

```ts
confirmationSigned?: (confirmation: ConfirmationRecord) => boolean;
```

**Omitted means `false`.** A bundle read straight off disk has no key set and no trust decision, so it can never confer eligibility. The only way to open the gate is to hand the evaluator a decision made somewhere else — `confirmationSignatureChecker(manifest)`, which verifies the signature once against the manifest's keys and returns a boolean.

That produces the seventh `ReviewReason`, `confirmation_unsigned`, in the order `confirmation_absent` → `confirmation_mismatch` → `confirmation_unsigned`: a confirmation the bundle merely *asserts* is now distinguishable from no confirmation at all.

`case dossier` takes `[--store DIR]`. Without it the dossier still renders and every confirmed case is reported as awaiting a signature:

```
### case-exact-in-scope — REVIEW     # no --store
### case-exact-in-scope — ELIGIBLE   # --store, key registered
```

### What the two layers do not cover

Approvals, outcomes, duplicate searches and assessments are enforced at the **store boundary**, not in `evaluateEligibility`. This is a deliberate deviation and it is written down: the gate never reads those records, and wiring them in would strip `impact_fit` and `effort` from the ranking vector and break eight further ranking assertions for no security gain. The store refuses to accept a bundle containing an unsigned one, which is the layer that can enforce it without lying about what the gate computes.

## 7. `path-guard.ts` and the F6 limit

`path-guard.ts` holds `withinRoot`, `isSensitivePath`, `isDisallowedPathString`, `assertDeclarablePath`, and `assertSafePath`. `patch.ts` imports `assertSafePath` instead of defining it, so the patch path and the declared path cannot drift apart. The four `Patch …` error messages are byte-identical to before, because `patch.test.ts` asserts on them.

`parseTaskContract` calls `assertDeclarablePath` over every `writablePaths` entry, after the capability check:

```
$ terminal221b case dossier traversal.json
terminal221b: writablePaths declares a disallowed path: ../../etc/passwd
```

**The limit of the parser.** The parser is synchronous and pure. It cannot `lstat`
or `realpath`, so a symlinked parent directory inside the workspace still parses;
that check lives in `assertSafePath`. **Both halves of that gap are now closed by
`executor.ts` (F17):** the segment walk runs before a path is treated as a
permission, against the workspace and again against the task worktree, and the
write set is then enforced by bubblewrap binding `/` read-only rather than by any
check in this file.

## 9. Retention

`terminal221b case store retention` is the verb that acts on a `retention` class, and it has two halves.

**The report mutates nothing.** It lists every source of every stored revision with its class, its age, and one of five statuses: `never-expires` (`operator_archive` has no window, because you chose to keep it), `unconfigured` (no window supplied, or the timestamp is unreadable), `within-window`, `past-window`, and `past-window-newest-revision`.

**No window is applied unless you write one.** How long outcome data may be kept was open decision 3 in the blueprint, and that is a policy question. It has since been answered: **`transient` 7 days, `case_metadata` 180 days, `local_diff` 180 days, and `operator_archive` never expires.** The reasoning is in the `DEFAULT_RETENTION_POLICY` docblock in `store.ts`, and the whole answer is a file you own and can edit:

```sh
terminal221b case store retention --store DIR --record-default-policy
```

writes `retention.json` into the store, which is then what every report reads. Editing it is a reviewable edit, not a code change. You can also pass windows per-run:

```sh
terminal221b case store retention --store DIR \
  --case-metadata-days 30 --transient-days 7 --local-diff-days 14
```

A class with no window reports `unconfigured` and is **not** treated as safe to delete. The report says so on its face, because a class with no window means nobody decided its retention, and treating that as permission to delete would be the tool inventing a policy.

**The purge cannot be blind.** The report prints a token derived from the purgeable set:

```
to purge case-exact-in-scope@1:
  terminal221b case store retention --purge sha256:3ddc3c31… --store DIR
```

`purgeExpired` recomputes that token against the store as it is now and refuses a mismatch, so a store that changed in between cannot be purged against a decision you never made.

**A purge removes a whole revision, never a single record.** A bundle's signature covers the whole bundle, so dropping one source out of the middle would rewrite signed bytes and silently invalidate every attestation in the file. Deleting a revision removes the evidence without falsifying any signature. Two consequences follow, and both are deliberate:

- The **newest revision of every entry is never purgeable**, so the store always keeps something current. It is still *reported* as past its window, so the debt is visible.
- A long-lived entry therefore accumulates revisions, and the stale content inside the newest one is not removable until you write a new revision without it, re-sign, and re-put. That residual is **F21**.

A content-addressed object is deleted only once **no surviving revision points at it**. Two puts of byte-identical bundles share one object, so purging one of them must not take the other's bytes with it.

Age is measured from `observedAt`, which **you** record. It describes your record-keeping, not the source — the same boundary the freshness review draws. Each removal is written to `transitions.jsonl` as a `purge` line naming the entry, the revision, and the sources that went.

## 10. What is not true yet

- A signature names a **key**, not a person. Anyone who can read the PEM produces a signature the store accepts, and `signedAt` is caller-chosen (F15).
- Only the two `local://` policy snapshots in the fixture are actually hashed. The other three sources are unreachable here and are reported as such rather than counted as verified (F16).
- The store can delete a **revision**, not the stale content inside a live one (F21). Retention within the newest revision needs a re-signed revision.
- The retention **windows are yours**, not the tool's. `DEFAULT_RETENTION_POLICY` is the answer to open decision 3 (7 / 180 / 180 days, archive never) and it reaches the store only through a `retention.json` you record. Until that file exists every class reports `unconfigured` and nothing is purgeable.
- The store is a directory, not a service. It tolerates concurrent writers on one host and is laid out so several hosts can share it, but there is no server and no multi-user story. On NFS, purge's object re-check can read stale directory attributes, so its guarantee that an object in use survives is weaker there.
- A task run acts on a contract now (F17 closed for the write path), but the actor is a single contract an operator hands the executor by hand. There is no scheduler, no queue, and no orchestration: `role` is still a label on a contract, and nothing reads it to decide who runs.
