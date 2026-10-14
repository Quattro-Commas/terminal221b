# 0001. Lock-free case store

Status: Accepted (owner decision). No ADR directory or format existed in this repository; this file sets a minimal Status / Context / Decision / Consequences layout.

## Context

The case store serialised writers with an advisory pid lock. Three successive lock designs failed review on the same family of problems: exists-then-create races, an empty-lock window that let a live lock be broken, release deleting a lock it no longer owned, EPERM read as "dead", takeover races, pids that mean nothing across hosts, clock-skew grace periods, races on the break file, old CLIs deleting a new lock format, false EEXIST over NFS, no backoff, init failing while locked, release masking the body's error, and leaked temp files. Each fix added a mechanism that created the next race. The store must also work when several hosts share it.

## Decision

Drop mutual exclusion and use optimistic concurrency built on one primitive, `createExclusive(final, bytes)`: write a temp file in the same directory, `link()` it to the final name, unlink the temp, fsync the directory. `link` fails with EEXIST instead of replacing, so exactly one writer wins and readers never see a partial file. A lost reply (EEXIST with the temp file at two links) counts as a win. Where hard links are unsupported it falls back to an exclusive create of the final name, which is still exclusive but can expose a partial file to a reader. `rename` is never used to claim a name.

- put: write the content-addressed object, claim `<n>.json` for n = newest + 1 (on EEXIST re-list and retry with 1-25 ms jitter, 20 attempts, then a contention error), append the `put` transition, then re-check the object and rewrite it from memory if missing. Revision numbers are never reused.
- trust: one file `keys/<sha256(keyId)>.json`; EEXIST means already trusted. The manifest's `trustedKeys` are a frozen base list; readers use the union.
- init: `mkdir -p`, exclusive manifest create; only the winner records `init`.
- transition log: each writer process appends to its own `transitions.d/<host>-<pid>-<random>.jsonl`, one framed buffer per record in a single write, lines under 4 KB. Readers merge the legacy `transitions.jsonl` and all per-writer logs, skip unparseable lines and collapse identical ones.
- reads: revision files are listed before the log is read; a read without a revision returns the newest vouched one; an unparseable revision with no transition is reported incomplete/unvouched, not corrupt.
- purge: record the `purge` line, then unlink the revision. Each object is renamed to `.condemned-*`, revisions and transitions are re-read, and it is renamed back if a surviving revision is vouched by its digest, otherwise deleted.
- leftovers: `.tmp-*` and `.condemned-*` files are ignored by readers and reported by `verify`. There is no cleanup command and no time-based logic.
- format: the manifest is version 2 (version 1 is still read). Any writer upgrades a version 1 store first, adding the regular file `bundles/.format-v2`, which old CLIs `readdir` as a directory and fail on (ENOTDIR). Fresh stores get it too. Directory listings skip dot-files.
- Testing: all filesystem calls go through an injectable `StoreIO` with `onStep(name)` hooks (`store-io.ts`), so each interleaving is reproduced deterministically.

## Consequences

- No lock to take over, break, leak or mis-release; init and trust never fail because another process is active.
- A reader can see a revision before its transition. `verify` may therefore report an in-flight write as unvouched, and it clears on the next run; no grace period is applied. Reads without a revision never serve an unvouched revision.
- Under heavy contention a put can fail with "too much contention" and must be retried.
- A purge can briefly hide an object; `verify` run in that window reports it missing. Over NFS the purge's re-check can read stale directory attributes, so "an object in use survives" is a local-filesystem guarantee only.
- Log ordering across writers is undefined; consumers look records up by (entry, revision).
- A crash can leave temp or condemned files, and a no-link filesystem can leave a partial revision file; `verify` reports both.
- Old CLIs are fenced by the version number and by `bundles/.format-v2` once a store has been written or initialised by this version; a store that is only read is not touched.
