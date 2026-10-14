import { describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCaseBundle } from '../src/case.js';
import { FIXTURE_NOW, fixtureBundle as unsignedFixture } from '../src/case-fixtures.js';
import {
  ATTESTED_KINDS,
  canonicalJson,
  confirmationSignatureChecker,
  DEFAULT_RETENTION_POLICY,
  defaultStoreRoot,
  entryName,
  getBundle,
  initStore,
  storePaths,
  withStoreLock,
  loadRetentionPolicy,
  localPathFor,
  payloadDigestOf,
  putBundle,
  purgeExpired,
  readManifest,
  saveRetentionPolicy,
  readPrivateKeyPem,
  readTransitions,
  recordIdOf,
  recordsOfKind,
  resolveStoreRoot,
  retentionReport,
  RETENTION_CLASSES,
  signBundle,
  signatureInput,
  trustKey,
  verifyBundleSignatures,
  verifyRecord,
  verifyStore,
  type RetentionWindows,
  type StoreManifest,
} from '../src/store.js';
import { evaluateEligibility } from '../src/ranking.js';

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const KEY_ID = 'operator-key';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const STRANGER = generateKeyPairSync('ed25519');

function spkiBase64(key = publicKey): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64');
}

function manifestWith(...keyIdsAndKeys: [string, ReturnType<typeof spkiBase64>][]): StoreManifest {
  return {
    version: 1,
    trustedKeys: keyIdsAndKeys.map(([keyId, der]) => ({ keyId, publicKeySpkiDerBase64: der, addedAt: FIXTURE_NOW })),
  };
}

const signedFixture = signBundle(unsignedFixture, privateKey, KEY_ID, FIXTURE_NOW);
const trusted = manifestWith([KEY_ID, spkiBase64()]);

/** A scratch store root that is deleted by the caller's temp dir lifetime. */
function scratchRoot(label: string): string {
  return mkdtempSync(join(tmpdir(), `t221b-${label}-`));
}

/** A scratch directory laid out so the fixture's local:// sources hash correctly. */
function scratchSourceTree(): string {
  const base = scratchRoot('sources');
  const policy = join(base, 'policies', 'example-inhouse-program');
  mkdirSync(policy, { recursive: true });
  writeFileSync(
    join(policy, '2026-09.json'),
    [
      'example-inhouse-program policy snapshot 2026-09',
      'in scope: https://example.invalid/programs/checkout-service/',
      'out of scope: https://example.invalid/programs/checkout-service/vendor-portal/',
    ].join('\n')
  );
  writeFileSync(
    join(policy, '2025-01.json'),
    [
      'example-inhouse-program policy snapshot 2025-01',
      'in scope: https://example.invalid/programs/checkout-service/',
    ].join('\n')
  );
  return base;
}

const baseDir = () => scratchSourceTree();

/* ------------------------------------------------------------------ */
/* canonical bytes                                                     */
/* ------------------------------------------------------------------ */

describe('canonical json', () => {
  it('sorts object keys ascending', () => {
    expect(canonicalJson({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
  });

  it('preserves array order, because array order is meaning', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('omits undefined rather than emitting a key with no value', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('recurses into nested objects and arrays', () => {
    expect(canonicalJson({ z: [{ b: 1, a: 2 }] })).toBe('{"z":[{"a":2,"b":1}]}');
  });

  it('produces the same bytes for the same data built in a different order', () => {
    const left = canonicalJson({ a: 1, b: [1, 2], c: { d: 'x', e: null } });
    const right = canonicalJson({ c: { e: null, d: 'x' }, b: [1, 2], a: 1 });
    expect(left).toBe(right);
  });

  it('refuses a value it cannot serialise deterministically', () => {
    expect(() => canonicalJson(Number.NaN)).toThrow(/non-finite/);
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(/non-finite/);
  });
});

/* ------------------------------------------------------------------ */
/* signature input and payload digests                                 */
/* ------------------------------------------------------------------ */

describe('what a signature commits to', () => {
  it('frames the context, kind, id and digest with one trailing newline', () => {
    const input = signatureInput('confirmation', 'cf-1', 'sha256:abc');
    expect(input.toString('utf8')).toBe(
      'terminal221b/record-signature/v1\nconfirmation\ncf-1\nsha256:abc\n'
    );
  });

  it('separates fields by newline so a field cannot be smuggled into the next one', () => {
    // A record id containing a newline must not be able to forge a different
    // kind/id pair by moving a newline.
    const a = signatureInput('confirmation', 'cf-1\napproval', 'sha256:abc').toString('utf8');
    const b = signatureInput('confirmation', 'cf-1', 'sha256:abc').toString('utf8');
    expect(a).not.toBe(b);
  });

  it('excludes the attestation from the payload digest, so signing is not self-referential', () => {
    const plain = recordsOfKind(unsignedFixture, 'confirmation')[0];
    const signed = recordsOfKind(signedFixture, 'confirmation')[0];
    expect(payloadDigestOf(signed)).toBe(payloadDigestOf(plain));
  });

  it('changes the payload digest when any attested field changes', () => {
    const before = payloadDigestOf(recordsOfKind(signedFixture, 'confirmation')[0]);
    const after = payloadDigestOf({
      ...recordsOfKind(signedFixture, 'confirmation')[0],
      statement: 'Confirmed something else entirely',
    });
    expect(after).not.toBe(before);
  });

  it('is stable across a JSON round trip through a file', () => {
    const record = recordsOfKind(signedFixture, 'confirmation')[0];
    const round = parseCaseBundle(JSON.parse(JSON.stringify(signedFixture))).confirmations[0];
    expect(payloadDigestOf(round)).toBe(payloadDigestOf(record));
  });
});

/* ------------------------------------------------------------------ */
/* sign and verify                                                     */
/* ------------------------------------------------------------------ */

describe('ed25519 record signatures', () => {
  it('reports a signed record as signed under a trusted key', () => {
    const record = recordsOfKind(signedFixture, 'confirmation')[0];
    const report = verifyRecord('confirmation', record, new Map([[KEY_ID, publicKey]]));
    expect(report.status).toBe('signed');
    expect(report.keyId).toBe(KEY_ID);
  });

  it('reports a record with no attestation as unsigned', () => {
    const report = verifyRecord(
      'confirmation',
      recordsOfKind(unsignedFixture, 'confirmation')[0],
      new Map([[KEY_ID, publicKey]])
    );
    expect(report.status).toBe('unsigned');
  });

  it('reports a signature made by an untrusted key as unknown-key', () => {
    const record = recordsOfKind(signedFixture, 'confirmation')[0];
    const report = verifyRecord('confirmation', record, new Map());
    expect(report.status).toBe('unknown-key');
  });

  it('reports a signature from the wrong key as bad-signature, not unknown-key', () => {
    // Same keyId, different private key: the key is trusted but the bytes do
    // not verify, which is a different and more alarming failure.
    const forged = signBundle(unsignedFixture, STRANGER.privateKey, KEY_ID, FIXTURE_NOW);
    const report = verifyRecord(
      'confirmation',
      recordsOfKind(forged, 'confirmation')[0],
      new Map([[KEY_ID, publicKey]])
    );
    expect(report.status).toBe('bad-signature');
  });

  it('reports an edited payload as digest-mismatch before it ever checks the signature', () => {
    const record = recordsOfKind(signedFixture, 'confirmation')[0];
    const edited = { ...record, statement: 'Confirmed after the fact' };
    const report = verifyRecord('confirmation', edited, new Map([[KEY_ID, publicKey]]));
    expect(report.status).toBe('digest-mismatch');
  });

  it('cannot be transplanted onto a different record id', () => {
    const record = recordsOfKind(signedFixture, 'confirmation')[0];
    const moved = { ...record, confirmationId: 'cf-somewhere-else' };
    const report = verifyRecord('confirmation', moved, new Map([[KEY_ID, publicKey]]));
    expect(report.status).not.toBe('signed');
  });

  it('cannot be transplanted onto a different record kind', () => {
    const approval = recordsOfKind(signedFixture, 'approval')[0];
    // A valid approval signature presented as a confirmation signature. The
    // framed kind is part of the signed bytes, so it can never verify. The
    // refusal happens even earlier: the id field for the claimed kind is
    // absent, and a record that does not carry its own identity is not
    // something to hand a verdict on.
    expect(() => verifyRecord('confirmation', approval, new Map([[KEY_ID, publicKey]]))).toThrow(
      /confirmation record has no confirmationId/
    );
    // And with the identity forced in, the framed kind still refuses it.
    const relabelled = { ...approval, confirmationId: (approval as unknown as { approvalId: string }).approvalId };
    expect(verifyRecord('confirmation', relabelled, new Map([[KEY_ID, publicKey]])).status).not.toBe('signed');
  });

  it('verifies every human record in the bundle', () => {
    const reports = verifyBundleSignatures(signedFixture, new Map([[KEY_ID, publicKey]]));
    const expected = ATTESTED_KINDS.reduce(
      (total, kind) => total + recordsOfKind(signedFixture, kind).length,
      0
    );
    expect(reports).toHaveLength(expected);
    expect(reports.every((report) => report.status === 'signed')).toBe(true);
  });

  it('names every record kind it covers', () => {
    expect([...ATTESTED_KINDS].sort()).toEqual([
      'approval',
      'assessment',
      'confirmation',
      'duplicateSearch',
      'outcome',
    ]);
  });

  it('reads the record id from the field that kind actually uses', () => {
    expect(recordIdOf(recordsOfKind(signedFixture, 'approval')[0], 'approval')).toBe(
      recordsOfKind(signedFixture, 'approval')[0].approvalId
    );
    expect(recordIdOf(recordsOfKind(signedFixture, 'duplicateSearch')[0], 'duplicateSearch')).toBe(
      recordsOfKind(signedFixture, 'duplicateSearch')[0].searchId
    );
  });
});

/* ------------------------------------------------------------------ */
/* source digests                                                      */
/* ------------------------------------------------------------------ */

describe('recomputing declared source digests', () => {
  it('maps a local:// uri against the base directory', () => {
    const base = scratchRoot('local');
    expect(localPathFor('local://policies/a.json', base)).toBe(join(base, 'policies', 'a.json'));
  });

  it('refuses a local:// uri that walks out of the base directory', () => {
    expect(localPathFor('local://../../etc/passwd', scratchRoot('escape'))).toBeUndefined();
  });

  it('refuses a file:// uri naming a host, because that is a remote file', () => {
    expect(localPathFor('file://elsewhere/policy.json', scratchRoot('host'))).toBeUndefined();
  });

  it('treats https as unverifiable here and never fetches it', () => {
    expect(localPathFor('https://example.invalid/policy.json', scratchRoot('remote'))).toBeUndefined();
  });

  it('verifies a policy snapshot whose bytes hash to the declared digest', async () => {
    const root = scratchRoot('verify-ok');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const result = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    const current = result.sources.find((entry) => entry.sourceId === 'src-policy-current');
    expect(current?.status).toBe('verified');
    expect(current?.actualDigest).toBe(current?.declaredDigest);
  });

  it('refuses a put when a local file no longer hashes to its declared digest', async () => {
    const root = scratchRoot('verify-bad');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    writeFileSync(join(base, 'policies', 'example-inhouse-program', '2026-09.json'), 'tampered');
    await expect(putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base })).rejects.toThrow(
      /src-policy-current.*declares.*but the bytes hash to/
    );
  });

  it('reports both digests so the operator can see which side moved', async () => {
    const root = scratchRoot('verify-detail');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    writeFileSync(join(base, 'policies', 'example-inhouse-program', '2026-09.json'), 'tampered');
    const error = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base }).catch(
      (e: Error) => e
    );
    const message = (error as Error).message;
    expect(message).toContain(
      `sha256:${createHash('sha256').update('tampered').digest('hex')}`
    );
  });

  it('refuses a put when a declared local source is absent entirely', async () => {
    const root = scratchRoot('verify-missing');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    // Removed, not rewritten: a file present with the wrong bytes is a
    // mismatch, and saying so would be a different claim from saying the
    // source is simply gone.
    rmSync(join(base, 'policies', 'example-inhouse-program', '2026-09.json'));
    await expect(
      putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base })
    ).rejects.toThrow(/its local bytes are not present/);
  });

  it('records a source it cannot reach here as unverifiable rather than pretending to have checked it', async () => {
    const root = scratchRoot('verify-remote');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const result = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    // file://reports/... names a HOST, not a path, so it is a remote file. It
    // is recorded as unverified rather than fetched: the store does no egress.
    const remote = result.sources.find((entry) => entry.sourceId === 'src-scanner-output');
    expect(remote?.uri).toBe('file://reports/fixture-scan.json');
    expect(remote?.status).toBe('unverifiable-here');
    expect(remote?.actualDigest).toBeUndefined();
  });

  it('verifies every source it can actually reach, and only those', async () => {
    const root = scratchRoot('verify-reach');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const result = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    expect(result.sources.filter((entry) => entry.status === 'verified').map((e) => e.sourceId)).toEqual([
      'src-policy-current',
      'src-policy-stale',
    ]);
    expect(result.sources.filter((entry) => entry.status === 'unverifiable-here')).toHaveLength(3);
  });
});

/* ------------------------------------------------------------------ */
/* store lifecycle                                                     */
/* ------------------------------------------------------------------ */

describe('store root and layout', () => {
  it('defaults outside any repository, under the XDG data home', () => {
    const previous = process.env.XDG_DATA_HOME;
    process.env.XDG_DATA_HOME = '/tmp/xdg-example';
    try {
      expect(defaultStoreRoot()).toBe('/tmp/xdg-example/terminal221b');
    } finally {
      if (previous === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = previous;
    }
  });

  it('falls back to the local share directory when XDG_DATA_HOME is unset', () => {
    const previous = process.env.XDG_DATA_HOME;
    delete process.env.XDG_DATA_HOME;
    try {
      expect(defaultStoreRoot()).toContain(join('.local', 'share', 'terminal221b'));
    } finally {
      if (previous !== undefined) process.env.XDG_DATA_HOME = previous;
    }
  });

  it('honours an explicit root', () => {
    expect(resolveStoreRoot('/tmp/explicit-store')).toBe('/tmp/explicit-store');
  });

  it('rejects an empty explicit root rather than silently using the default', () => {
    expect(() => resolveStoreRoot('')).toThrow(/--store requires a directory path/);
    expect(() => resolveStoreRoot('   ')).toThrow(/--store requires a directory path/);
  });

  it('creates the layout and an empty trust list on init', async () => {
    const root = scratchRoot('init');
    await initStore(root, FIXTURE_NOW);
    expect(readManifest(root)).toEqual({ version: 1, trustedKeys: [] });
    expect(readdirSync(root).sort()).toEqual(
      expect.arrayContaining(['bundles', 'manifest.json', 'objects', 'transitions.jsonl'])
    );
  });

  it('is idempotent, and does not discard keys on a second init', async () => {
    const root = scratchRoot('init-twice');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await initStore(root, FIXTURE_NOW);
    expect(readManifest(root).trustedKeys).toHaveLength(1);
  });

  it('points at the command that creates a missing store', () => {
    expect(() => readManifest(scratchRoot('absent'))).toThrow(/case store init --store/);
  });

  it('never writes a private key into the store', async () => {
    const root = scratchRoot('no-key');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const marker = pem.split('\n')[1];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const at = join(dir, entry.name);
        // Dirents do not follow symlinks; a linked directory is still walked.
        if (entry.isDirectory() || (entry.isSymbolicLink() && statSync(at).isDirectory())) walk(at);
        else expect(readFileSync(at, 'utf8')).not.toContain(marker);
      }
    };
    walk(root);
  });
});

/* ------------------------------------------------------------------ */
/* trust keys                                                          */
/* ------------------------------------------------------------------ */

describe('trusting a key', () => {
  it('stores the public key and nothing else', async () => {
    const root = scratchRoot('trust');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey, label: 'laptop' }, FIXTURE_NOW);
    const entry = readManifest(root).trustedKeys[0];
    expect(entry.keyId).toBe(KEY_ID);
    expect(entry.label).toBe('laptop');
    expect(Object.keys(entry).sort()).toEqual(['addedAt', 'keyId', 'label', 'publicKeySpkiDerBase64']);
  });

  it('round-trips a DER buffer into a usable verifier', async () => {
    const root = scratchRoot('trust-der');
    await initStore(root, FIXTURE_NOW);
    trustKey(
      root,
      { keyId: KEY_ID, publicKey: publicKey.export({ type: 'spki', format: 'der' }) },
      FIXTURE_NOW
    );
    const checker = confirmationSignatureChecker(readManifest(root));
    expect(checker(recordsOfKind(signedFixture, 'confirmation')[0])).toBe(true);
  });

  it('refuses a duplicate keyId, so trust cannot be silently widened', async () => {
    const root = scratchRoot('trust-dup');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    expect(() => trustKey(root, { keyId: KEY_ID, publicKey: STRANGER.publicKey }, FIXTURE_NOW)).toThrow(
      /already trusted/
    );
  });

  it('rejects a manifest entry that is not a usable public key', async () => {
    const root = scratchRoot('trust-broken');
    await initStore(root, FIXTURE_NOW);
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({
        version: 1,
        trustedKeys: [{ keyId: 'bad', publicKeySpkiDerBase64: 'bm90LWEtkeyk=', addedAt: FIXTURE_NOW }],
      })
    );
    expect(() => confirmationSignatureChecker(readManifest(root))).toThrow(/not a usable public key/);
  });

  it('refuses a private key file presented where a signing key is expected', () => {
    const dir = scratchRoot('keyfile');
    const pemPath = join(dir, 'key.pem');
    writeFileSync(pemPath, publicKey.export({ type: 'spki', format: 'pem' }) as string);
    expect(() => readPrivateKeyPem(pemPath)).toThrow(/does not contain a PRIVATE KEY block/);
  });
});

/* ------------------------------------------------------------------ */
/* put / get / verify                                                  */
/* ------------------------------------------------------------------ */

describe('accepting a bundle', () => {
  it('refuses an unsigned human record and names it', async () => {
    const root = scratchRoot('put-unsigned');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await expect(
      putBundle(root, unsignedFixture, { now: FIXTURE_NOW, baseDir: baseDir() })
    ).rejects.toThrow(/confirmation cf-exact-in-scope is unsigned/);
  });

  it('refuses a bundle whose only signature comes from an untrusted key', async () => {
    const root = scratchRoot('put-untrusted');
    await initStore(root, FIXTURE_NOW);
    await expect(
      putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() })
    ).rejects.toThrow(/unknown-key/);
  });

  it('writes nothing at all when it refuses', async () => {
    const root = scratchRoot('put-atomic');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, unsignedFixture, { now: FIXTURE_NOW, baseDir: baseDir() }).catch(() => undefined);
    expect(readdirSync(join(root, 'bundles'))).toEqual([]);
  });

  it('stores a fully signed and digest-verified bundle', async () => {
    const root = scratchRoot('put-ok');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const result = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    expect(result.entry).toBe('case-exact-in-scope');
    expect(result.revision).toBe(1);
    expect(readFileSync(join(root, 'bundles', result.entry, '1.json'), 'utf8')).toContain('"taskId"');
  });

  it('keeps each new revision instead of overwriting the last', async () => {
    const root = scratchRoot('put-revisions');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const first = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    const second = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    expect(second.revision).toBe(first.revision + 1);
    expect(readdirSync(join(root, 'bundles', 'case-exact-in-scope')).sort()).toEqual(['1.json', '2.json']);
  });

  it('logs a transition for each accepted put', async () => {
    const root = scratchRoot('put-log');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    const lines = readFileSync(join(root, 'transitions.jsonl'), 'utf8').trim().split('\n');
    expect(lines.map((line) => JSON.parse(line).action)).toEqual(['init', 'trust', 'put']);
  });

  it('files a multi-case bundle under the first case, keeping one scope per entry', async () => {
    const root = scratchRoot('put-multicase');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    // A bundle is the unit, not a case: it carries one scope and one policy
    // snapshot for every case inside it. Splitting per case would let a later
    // revision move the snapshot while an earlier case's records stayed behind.
    const result = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    expect(signedFixture.cases.length).toBeGreaterThan(1);
    expect(result.entry).toBe(signedFixture.cases[0].caseId);
  });

  it('refuses an entry name that would walk out of the bundles directory', async () => {
    const root = scratchRoot('put-hostile-entry');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await expect(
      putBundle(root, signedFixture, {
        now: FIXTURE_NOW,
        baseDir: baseDir(),
        entry: '../../escape',
      })
    ).rejects.toThrow(/store entry name must be letters, digits, dot, dash or underscore/);
  });

  it('refuses a bundle carrying no cases at all, because it has nothing to file under', async () => {
    // validateCaseBundle rejects it first, and it should: every confirmation,
    // search and task in the bundle points at a case that is no longer there.
    // Naming the entry is the second line of defence, tested directly below.
    const root = scratchRoot('put-nocases');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await expect(
      putBundle(root, { ...signedFixture, cases: [] }, { now: FIXTURE_NOW, baseDir: baseDir() })
    ).rejects.toThrow(/is not in the bundle/);
    expect(() => entryName({ ...signedFixture, cases: [] })).toThrow(
      /a bundle with no cases has nothing to file it under/
    );
  });

  it('refuses a bundle that is not internally consistent before touching the store', async () => {
    const root = scratchRoot('put-inconsistent');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const broken = { ...signedFixture, evidence: [] };
    await expect(putBundle(root, broken, { now: FIXTURE_NOW, baseDir: baseDir() })).rejects.toThrow(
      /not internally consistent/
    );
  });
});

describe('reading a bundle back out', () => {
  it('returns the stored bundle at its last revision by default', async () => {
    const root = scratchRoot('get-last');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    const got = await getBundle(root, 'case-exact-in-scope', undefined, {
      now: FIXTURE_NOW,
      baseDir: baseDir(),
    });
    expect(got.revision).toBe(2);
    expect(got.bundle.cases[0].caseId).toBe('case-exact-in-scope');
  });

  it('re-verifies signatures on the way out, not only on the way in', async () => {
    const root = scratchRoot('get-reverify');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    // Revoke trust by rewriting the manifest: the stored bytes are unchanged.
    writeFileSync(join(root, 'manifest.json'), JSON.stringify({ version: 1, trustedKeys: [] }));
    await expect(
      getBundle(root, 'case-exact-in-scope', 1, { now: FIXTURE_NOW, baseDir: baseDir() })
    ).rejects.toThrow(/is unknown-key/);
  });

  it('can report problems instead of throwing when asked not to', async () => {
    const root = scratchRoot('get-lenient');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    writeFileSync(join(root, 'manifest.json'), JSON.stringify({ version: 1, trustedKeys: [] }));
    const got = await getBundle(root, 'case-exact-in-scope', 1, {
      now: FIXTURE_NOW,
      baseDir: baseDir(),
      strict: false,
    });
    expect(got.report.ok).toBe(false);
    expect(got.report.signatures.every((entry) => entry.status === 'unknown-key')).toBe(true);
  });

  it('says so when the store holds nothing for a case', async () => {
    const root = scratchRoot('get-absent');
    await initStore(root, FIXTURE_NOW);
    await expect(
      getBundle(root, 'case-nope', undefined, { now: FIXTURE_NOW, baseDir: baseDir() })
    ).rejects.toThrow(/holds no revisions/);
  });

  it('lists the revisions it does hold when asked for one it does not', async () => {
    const root = scratchRoot('get-missing-rev');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    await expect(
      getBundle(root, 'case-exact-in-scope', 7, { now: FIXTURE_NOW, baseDir: baseDir() })
    ).rejects.toThrow(/no revision 7.*it has 1/);
  });
});

describe('verifying the whole store', () => {
  it('passes on a store that was just written', async () => {
    const root = scratchRoot('verify-all-ok');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base });
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
    expect(report.problems).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entries).toHaveLength(1);
  });

  it('detects a bundle edited on disk after it was stored', async () => {
    const root = scratchRoot('verify-all-tampered');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base });
    const at = join(root, 'bundles', 'case-exact-in-scope', '1.json');
    writeFileSync(at, readFileSync(at, 'utf8').replace('USD 500', 'USD 500000'));
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
    expect(report.ok).toBe(false);
    expect(report.problems.join('\n')).toMatch(/no longer hashes to its recorded digest/);
  });

  it('detects a deleted stored object', async () => {
    const root = scratchRoot('verify-all-object');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    const result = await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base });
    for (const name of readdirSync(join(root, 'objects'))) {
      if (name.includes(result.bundleDigest.replace(':', '-'))) {
        writeFileSync(join(root, 'objects', name), 'clobbered');
      }
    }
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
    expect(report.problems.join('\n')).toMatch(/no intact stored object/);
  });

  it('re-checks local digests too, not only bundle integrity', async () => {
    const root = scratchRoot('verify-all-digest');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base });
    writeFileSync(join(base, 'policies', 'example-inhouse-program', '2026-09.json'), 'changed later');
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
    expect(report.problems.join('\n')).toMatch(/src-policy-current/);
  });
});

/* ------------------------------------------------------------------ */
/* the gate the store feeds                                            */
/* ------------------------------------------------------------------ */

describe('the eligibility gate reads the store trust decision', () => {
  const caseRecord = signedFixture.cases.find((entry) => entry.caseId === 'case-exact-in-scope')!;

  it('is closed when the caller supplies no trust decision', () => {
    const result = evaluateEligibility(caseRecord, signedFixture, {
      now: FIXTURE_NOW,
      policyMaxAgeDays: 90,
    });
    expect(result.eligibility).toBe('review');
    expect(result.reviewReasons).toContain('confirmation_unsigned');
  });

  it('opens only for a key the store actually trusts', () => {
    const result = evaluateEligibility(caseRecord, signedFixture, {
      now: FIXTURE_NOW,
      policyMaxAgeDays: 90,
      confirmationSigned: confirmationSignatureChecker(trusted),
    });
    expect(result.eligibility).toBe('eligible');
    expect(result.reviewReasons).toEqual([]);
  });

  it('stays closed for a trusted key that did not sign this bundle', () => {
    const result = evaluateEligibility(caseRecord, signedFixture, {
      now: FIXTURE_NOW,
      policyMaxAgeDays: 90,
      confirmationSigned: confirmationSignatureChecker(manifestWith(['other-key', spkiBase64(STRANGER.publicKey)])),
    });
    expect(result.eligibility).toBe('review');
  });
});

/* ------------------------------------------------------------------ */
/* the end-to-end path the CLI drives                                  */
/* ------------------------------------------------------------------ */

describe('init, sign, put, get, verify in sequence', () => {
  it('carries a bundle from an unsigned file to a verified store entry', async () => {
    const root = scratchRoot('e2e');
    const base = baseDir();
    const source = join(root, 'incoming.json');
    const keyPem = join(root, 'operator-key.pem');
    writeFileSync(source, JSON.stringify(unsignedFixture, null, 2));
    writeFileSync(keyPem, privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);

    // 1. init + trust, using only the public half
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);

    // 2. sign with the private key, which never entered the store
    const signedText = JSON.stringify(
      signBundle(parseCaseBundle(JSON.parse(readFileSync(source, 'utf8'))), readPrivateKeyPem(keyPem), KEY_ID, FIXTURE_NOW),
      null,
      2
    );

    // 3. put
    const put = await putBundle(root, parseCaseBundle(JSON.parse(signedText)), {
      now: FIXTURE_NOW,
      baseDir: base,
    });
    expect(put.revision).toBe(1);

    // 4. get
    const got = await getBundle(root, put.entry, undefined, { now: FIXTURE_NOW, baseDir: base });
    expect(got.report.ok).toBe(true);

    // 5. verify
    const all = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
    expect(all.ok).toBe(true);
    expect(all.signatures.every((entry) => entry.status === 'signed')).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* retention enforcement                                               */
/* ------------------------------------------------------------------ */

/**
 * The fixture sources, with the age each has at FIXTURE_NOW:
 *   src-policy-current   2026-09-28T09:00:00Z   2d   case_metadata
 *   src-policy-stale     2025-01-05T09:00:00Z   603d case_metadata
 *   src-scanner-output   2026-09-27T18:30:00Z   2d   transient
 *   src-fixture-notes    2026-09-29T20:00:00Z   0d   case_metadata
 *   src-operator-receipt 2026-09-10T11:00:00Z   20d  operator_archive
 */
const NO_WINDOWS = {};
const POLICY = { case_metadata: 30, transient: 7 };

async function storedStore(label: string, revisions = 1): Promise<string> {
  const root = scratchRoot(label);
  await initStore(root, FIXTURE_NOW);
  trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
  for (let n = 0; n < revisions; n += 1) {
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
  }
  return root;
}

describe('retention is a policy input, not a hardcoded guess', () => {
  it('reports every class as unconfigured when no window is supplied', async () => {
    const root = await storedStore('ret-unconfigured');
    const report = retentionReport(root, NO_WINDOWS, FIXTURE_NOW);
    expect(report.counts.unconfigured).toBe(4);
    expect(report.counts['never-expires']).toBe(1);
    expect(report.purgeable).toEqual([]);
  });

  it('never treats an unconfigured class as safe enough to delete', async () => {
    const root = await storedStore('ret-unconfigured-safe');
    const report = retentionReport(root, NO_WINDOWS, FIXTURE_NOW);
    expect(report.rows.some((row) => row.status === 'past-window')).toBe(false);
    expect(() => purgeExpired(root, NO_WINDOWS, FIXTURE_NOW, report.token)).toThrow(
      /nothing is past its retention window/
    );
  });

  it('treats operator_archive as never expiring, because the operator chose to keep it', async () => {
    const root = await storedStore('ret-archive');
    const report = retentionReport(root, { ...POLICY, case_metadata: 0 }, FIXTURE_NOW);
    const archive = report.rows.find((row) => row.sourceId === 'src-operator-receipt');
    expect(archive?.status).toBe('never-expires');
    expect(archive?.ageDays).toBe(20);
  });

  it('measures age from the operator-recorded observedAt, in whole days', async () => {
    const root = await storedStore('ret-age');
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    const ages = Object.fromEntries(report.rows.map((row) => [row.sourceId, row.ageDays]));
    expect(ages['src-policy-current']).toBe(2);
    expect(ages['src-policy-stale']).toBe(633);
    expect(ages['src-scanner-output']).toBe(2);
    expect(ages['src-fixture-notes']).toBe(0);
  });

  it('classifies each source against the window its own class carries', async () => {
    const root = await storedStore('ret-classify');
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    const byId = Object.fromEntries(report.rows.map((row) => [row.sourceId, row.status]));
    expect(byId['src-policy-stale']).toBe('past-window-newest-revision');
    expect(byId['src-policy-current']).toBe('within-window');
    expect(byId['src-scanner-output']).toBe('within-window');
    expect(byId['src-fixture-notes']).toBe('within-window');
  });

  it('reports a negative age rather than pretending a future timestamp is old', async () => {
    const root = await storedStore('ret-future');
    const report = retentionReport(root, { case_metadata: -1 }, FIXTURE_NOW);
    expect(report.rows.some((row) => (row.ageDays ?? 0) < 0)).toBe(false);
  });
});

describe('a purge cannot happen without a report having been read', () => {
  it('marks the newest revision past its window but never purgeable', async () => {
    const root = await storedStore('ret-newest', 1);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    expect(report.counts['past-window-newest-revision']).toBeGreaterThan(0);
    expect(report.purgeable).toEqual([]);
  });

  it('makes an older revision purgeable once a newer one exists', async () => {
    const root = await storedStore('ret-older', 2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    expect(report.purgeable).toEqual(['case-exact-in-scope@1']);
  });

  it('refuses a token that was not produced by a report of this store', async () => {
    const root = await storedStore('ret-badtoken', 2);
    const before = readdirSync(join(root, 'bundles', 'case-exact-in-scope'));
    expect(() => purgeExpired(root, POLICY, FIXTURE_NOW, 'sha256:not-a-real-token')).toThrow(
      /retention token does not match this store as it is now/
    );
    expect(readdirSync(join(root, 'bundles', 'case-exact-in-scope'))).toEqual(before);
  });

  it('refuses a token that has gone stale because the store changed', async () => {
    const root = await storedStore('ret-stale-token', 2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: baseDir() });
    expect(() => purgeExpired(root, POLICY, FIXTURE_NOW, report.token)).toThrow(
      /retention token does not match/
    );
  });

  it('refuses to purge when nothing is past its window, and says to run the report', async () => {
    const root = await storedStore('ret-nothing', 1);
    expect(() => purgeExpired(root, POLICY, FIXTURE_NOW, 'anything')).toThrow(
      /run the report first and look at it/
    );
  });
});

describe('purging removes a revision, not a record', () => {
  it('removes exactly the revision the report named, and no other', async () => {
    const root = await storedStore('ret-purge', 2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    const result = purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    expect(result.removed).toHaveLength(1);
    expect(result.removed[0].entry).toBe('case-exact-in-scope');
    expect(result.removed[0].revision).toBe(1);
    expect(result.removed[0].sources).toContain('src-policy-stale');
    expect(readdirSync(join(root, 'bundles', 'case-exact-in-scope'))).toEqual(['2.json']);
  });

  it('always leaves the newest revision in place', async () => {
    const root = await storedStore('ret-keep-newest', 2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    expect(readdirSync(join(root, 'bundles', 'case-exact-in-scope'))).toEqual(['2.json']);
  });

  it('keeps a shared object that a surviving revision still points at', async () => {
    // Two puts of byte-identical bundles share one content-addressed object, so
    // purging revision 1 must NOT take revision 2's bytes with it. Deleting it
    // would make the store fail its own integrity check with nothing tampered.
    const root = await storedStore('ret-shared-object', 2);
    const digest = readTransitions(root).find((line) => line.revision === 1)?.bundleDigest;
    expect(digest).toBeDefined();
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    expect(existsSync(join(root, 'objects', (digest as string).replace(':', '-')))).toBe(true);
  });

  it('removes an object that no surviving revision points at', async () => {
    const root = scratchRoot('ret-orphan-object');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    const base = baseDir();
    // Different bytes, so the two revisions get different object files.
    await putBundle(root, signedFixture, { now: FIXTURE_NOW, baseDir: base });
    const second = signBundle(unsignedFixture, privateKey, KEY_ID, '2026-09-30T13:00:00Z');
    await putBundle(root, second, { now: FIXTURE_NOW, baseDir: base });
    const digests = readTransitions(root)
      .filter((line) => line.bundleDigest)
      .map((line) => line.bundleDigest as string);
    expect(new Set(digests).size).toBe(2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    expect(report.purgeable).toEqual(['case-exact-in-scope@1']);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    expect(existsSync(join(root, 'objects', digests[0].replace(':', '-')))).toBe(false);
    expect(existsSync(join(root, 'objects', digests[1].replace(':', '-')))).toBe(true);
  });

  it('logs a purge transition naming what went and why', async () => {
    const root = await storedStore('ret-log', 2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    const purge = readTransitions(root).filter((line) => line.action === 'purge');
    expect(purge).toHaveLength(1);
    expect(purge[0].entry).toBe('case-exact-in-scope');
    expect(purge[0].revision).toBe(1);
    expect(purge[0].detail).toMatch(/past its retention window/);
  });

  it('leaves a store that still verifies, because it removed a revision rather than rewriting one', async () => {
    const root = await storedStore('ret-consistent', 2);
    const base = baseDir();
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    const verified = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
    expect(verified.problems).toEqual([]);
    expect(verified.entries.map((entry) => entry.revision)).toEqual([2]);
  });

  it('does not falsify any surviving signature, because it never rewrote a signed bundle', async () => {
    const root = await storedStore('ret-signatures', 2);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
    const remaining = await getBundle(root, 'case-exact-in-scope', 2, {
      now: FIXTURE_NOW,
      baseDir: baseDir(),
    });
    expect(remaining.report.signatures.every((entry) => entry.status === 'signed')).toBe(true);
  });

  it('changes nothing when only the report is called', async () => {
    const root = await storedStore('ret-pure', 2);
    const before = readdirSync(join(root, 'bundles', 'case-exact-in-scope'));
    const transitions = readTransitions(root).length;
    retentionReport(root, POLICY, FIXTURE_NOW);
    expect(readdirSync(join(root, 'bundles', 'case-exact-in-scope'))).toEqual(before);
    expect(readTransitions(root)).toHaveLength(transitions);
  });
});

/* ------------------------------------------------------------------ */
/* the retention policy file: the answer to open decision 3           */
/* ------------------------------------------------------------------ */

describe('the retention policy is a file the operator edits, not a code default', () => {
  it('reports every class unconfigured when the store has no policy file', async () => {
    const root = await storedStore('pol-absent');
    expect(loadRetentionPolicy(root)).toBeUndefined();
  });

  it('records a policy and reads it back', async () => {
    const root = await storedStore('pol-write');
    const saved = saveRetentionPolicy(root, DEFAULT_RETENTION_POLICY, FIXTURE_NOW);
    expect(saved.overwritten).toBe(false);
    expect(loadRetentionPolicy(root)?.windows).toEqual(DEFAULT_RETENTION_POLICY);
  });

  it('never gives operator_archive a window, because the operator chose to keep it', async () => {
    const root = await storedStore('pol-archive');
    saveRetentionPolicy(root, { ...DEFAULT_RETENTION_POLICY, operator_archive: 1 } as RetentionWindows, FIXTURE_NOW);
    const file = JSON.parse(readFileSync(join(root, 'retention.json'), 'utf8'));
    expect(Object.keys(file.windows)).not.toContain('operator_archive');
    expect(loadRetentionPolicy(root)?.windows).not.toHaveProperty('operator_archive');
  });

  it('writes the classes in a stable order so a diff is readable', async () => {
    const root = await storedStore('pol-order');
    saveRetentionPolicy(root, { local_diff: 5, transient: 1, case_metadata: 9 }, FIXTURE_NOW);
    expect(Object.keys(JSON.parse(readFileSync(join(root, 'retention.json'), 'utf8')).windows)).toEqual([
      'transient',
      'case_metadata',
      'local_diff',
    ]);
  });

  it('says in the file that it is the answer to open decision 3', async () => {
    const root = await storedStore('pol-note');
    saveRetentionPolicy(root, DEFAULT_RETENTION_POLICY, FIXTURE_NOW);
    expect(JSON.parse(readFileSync(join(root, 'retention.json'), 'utf8')).note).toMatch(/open decision 3/);
  });

  it('replaces a policy rather than appending, and says that it replaced one', async () => {
    const root = await storedStore('pol-replace');
    saveRetentionPolicy(root, DEFAULT_RETENTION_POLICY, FIXTURE_NOW);
    const second = saveRetentionPolicy(root, { transient: 3 }, FIXTURE_NOW);
    expect(second.overwritten).toBe(true);
    expect(loadRetentionPolicy(root)?.windows).toEqual({ transient: 3 });
  });

  it('logs the change as its own transition, so the log records the policy', async () => {
    const root = await storedStore('pol-log');
    saveRetentionPolicy(root, DEFAULT_RETENTION_POLICY, FIXTURE_NOW);
    const line = readTransitions(root).find((item) => item.action === 'retention-policy-recorded');
    expect(line?.detail).toMatch(/transient=7d/);
  });

  /**
   * The store and the schema now share one `RETENTION_CLASSES`, so a "the two
   * lists match" test would compare a binding with itself. This is the drift
   * that survives that fix instead: a class added to the schema without anyone
   * deciding a window for it. Such a class reports `unconfigured` forever and is
   * therefore never purged — silently, with no error anywhere. So exactly one
   * class may lack a window, and it must be the archive.
   */
  it('gives every class a window except the one archive the operator keeps forever', () => {
    const windowless = RETENTION_CLASSES.filter((key) => !(key in DEFAULT_RETENTION_POLICY));
    expect(windowless).toEqual(['operator_archive']);
  });

  it('records the approved 7 / 180 / 180 windows rather than a guess', () => {
    expect(DEFAULT_RETENTION_POLICY).toEqual({
      transient: 7,
      case_metadata: 180,
      local_diff: 180,
    });
  });

  it('refuses a file that names a class the schema does not have', async () => {
    const root = await storedStore('pol-unknown');
    writeFileSync(
      join(root, 'retention.json'),
      JSON.stringify({ version: 1, windows: { evidence_forever: 30 } })
    );
    expect(() => loadRetentionPolicy(root)).toThrow(/unknown retention class: evidence_forever/);
  });

  it('refuses a window that is not a whole number of days', async () => {
    const root = await storedStore('pol-fraction');
    writeFileSync(join(root, 'retention.json'), JSON.stringify({ version: 1, windows: { transient: 1.5 } }));
    expect(() => loadRetentionPolicy(root)).toThrow(/not a whole number of days/);
  });

  it('refuses a file from a future version rather than guessing at it', async () => {
    const root = await storedStore('pol-version');
    writeFileSync(join(root, 'retention.json'), JSON.stringify({ version: 2, windows: { transient: 7 } }));
    expect(() => loadRetentionPolicy(root)).toThrow(/this store understands version 1/);
  });

  it('refuses a corrupt file with the file named, not a stack trace', async () => {
    const root = await storedStore('pol-corrupt');
    writeFileSync(join(root, 'retention.json'), '{ not json');
    expect(() => loadRetentionPolicy(root)).toThrow(/is not readable JSON/);
  });

  it('actually changes what is purgeable once the policy exists', async () => {
    const root = await storedStore('pol-effect', 2);
    expect(retentionReport(root, {}, FIXTURE_NOW).purgeable).toEqual([]);
    saveRetentionPolicy(root, DEFAULT_RETENTION_POLICY, FIXTURE_NOW);
    // case_metadata 180d and src-policy-stale is 633d old, so revision 1 goes.
    expect(retentionReport(root, DEFAULT_RETENTION_POLICY, FIXTURE_NOW).purgeable).toEqual([
      'case-exact-in-scope@1',
    ]);
  });

  it('ships a starting policy that is a position, not a measurement', () => {
    expect(DEFAULT_RETENTION_POLICY).toEqual({ transient: 7, case_metadata: 180, local_diff: 180 });
  });
});

describe('the store lock', () => {
  it('refuses a second taker while it is held, and is released afterwards', () => {
    const paths = storePaths(scratchRoot('lock-held'));
    withStoreLock(paths, () => {
      expect(() => withStoreLock(paths, () => 'second')).toThrow(/locked by process/);
    });
    expect(existsSync(paths.lock)).toBe(false);
    expect(withStoreLock(paths, () => 'after')).toBe('after');
  });

  it('takes over a lock left by a process that is gone, in either lock format', () => {
    const paths = storePaths(scratchRoot('lock-stale'));
    mkdirSync(paths.root, { recursive: true });
    for (const holder of ['999999999\n', '999999999:abcd\n', 'not a pid\n', '']) {
      writeFileSync(paths.lock, holder);
      const held = withStoreLock(paths, () => readFileSync(paths.lock, 'utf8'));
      expect(held).toMatch(new RegExp(`^${process.pid}:[0-9a-f]{16}\\n$`));
      expect(existsSync(paths.lock)).toBe(false);
    }
  });

  it('never deletes a lock it no longer owns', () => {
    const paths = storePaths(scratchRoot('lock-owner'));
    withStoreLock(paths, () => {
      // Someone else's lock now sits at the path (as after a takeover).
      writeFileSync(paths.lock, '999999999:feedfacefeedface\n');
    });
    expect(readFileSync(paths.lock, 'utf8')).toBe('999999999:feedfacefeedface\n');
  });

  it('treats a holder owned by another user as alive', () => {
    // process.kill(pid, 0) throws EPERM for a live process of another user.
    const paths = storePaths(scratchRoot('lock-eperm'));
    mkdirSync(paths.root, { recursive: true });
    writeFileSync(paths.lock, '424242:0123456789abcdef\n');
    const kill = vi.spyOn(process, 'kill').mockImplementation(() => {
      throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
    });
    try {
      expect(() => withStoreLock(paths, () => 'taken')).toThrow(/locked by process 424242/);
    } finally {
      kill.mockRestore();
    }
    expect(readFileSync(paths.lock, 'utf8')).toBe('424242:0123456789abcdef\n');
  });

  it('leaves no temp or stale files behind', () => {
    const paths = storePaths(scratchRoot('lock-clean'));
    mkdirSync(paths.root, { recursive: true });
    writeFileSync(paths.lock, '999999999\n');
    withStoreLock(paths, () => undefined);
    expect(readdirSync(paths.root).filter((n) => n.includes('.lock') || n.endsWith('.tmp'))).toEqual([]);
  });

  it('initStore never truncates the transitions already recorded', async () => {
    const root = scratchRoot('init-keep');
    const paths = await initStore(root, FIXTURE_NOW);
    const before = readFileSync(paths.transitions, 'utf8');
    expect(before.length).toBeGreaterThan(0);
    await initStore(root, FIXTURE_NOW);
    expect(readFileSync(paths.transitions, 'utf8')).toBe(before);
  });
});
