import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  writeSync,
  closeSync,
  fsyncSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FIXTURE_NOW, fixtureBundle as unsignedFixture } from '../src/case-fixtures.js';
import {
  getBundle,
  initStore,
  listEntries,
  putBundle,
  purgeExpired,
  readKeyDirectory,
  readManifest,
  readTransitionLog,
  readTransitions,
  retentionReport,
  sha256,
  signBundle,
  trustKey,
  verifyStore,
} from '../src/store.js';
import { createExclusive, nodeIO, resolveContext, type StoreContext } from '../src/store-io.js';

/*
 * These tests drive the races the lock-free store is designed around. Each one
 * installs an `onStep` hook that performs the competing write at the exact step
 * under test, so the interleaving is deterministic rather than hoped for.
 */

const KEY_ID = 'operator-key';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const OTHER = generateKeyPairSync('ed25519');
const ENTRY = 'case-exact-in-scope';
const POLICY = { case_metadata: 30, transient: 7 };
const signedX = signBundle(unsignedFixture, privateKey, KEY_ID, FIXTURE_NOW);
const signedY = signBundle(unsignedFixture, privateKey, KEY_ID, '2026-09-30T13:00:00Z');
const noSleep = { sleep: async () => undefined };

function scratch(label: string): string {
  return mkdtempSync(join(tmpdir(), `t221b-${label}-`));
}

function sourceTree(): string {
  const base = scratch('sources');
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

const BASE = sourceTree();

async function freshStore(label: string): Promise<string> {
  const root = scratch(label);
  await initStore(root, FIXTURE_NOW);
  trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
  return root;
}

const put = (root: string, bundle = signedX, context?: StoreContext) =>
  putBundle(root, bundle, { now: FIXTURE_NOW, baseDir: BASE, context });

function errno(code: string): Error {
  return Object.assign(new Error(`simulated ${code}`), { code });
}

function revisionFiles(root: string, entry = ENTRY): string[] {
  return readdirSync(join(root, 'bundles', entry)).sort();
}

function objectPath(root: string, digest: string): string {
  return join(root, 'objects', digest.replace(':', '-'));
}

describe('two puts claiming the same revision number', () => {
  it('lets the loser take n+1, and both end up vouched', async () => {
    const root = await freshStore('race-put');
    let nested: Awaited<ReturnType<typeof put>> | undefined;
    let fired = false;
    const loser = await put(root, signedX, {
      ...noSleep,
      onStep: async (name) => {
        // Both writers have computed n=1; the other one claims it first.
        if (name === 'put:before-claim' && !fired) {
          fired = true;
          nested = await put(root, signedX);
        }
      },
    });
    expect(nested?.revision).toBe(1);
    expect(loser.revision).toBe(2);
    expect(revisionFiles(root)).toEqual(['1.json', '2.json']);
    const vouched = readTransitions(root).filter((t) => t.action === 'put').map((t) => t.revision);
    expect(vouched.sort()).toEqual([1, 2]);
    expect((await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE })).ok).toBe(true);
  });

  it('gives up with an explicit contention error after 20 attempts', async () => {
    const root = await freshStore('race-contention');
    let sleeps = 0;
    await expect(
      put(root, signedX, {
        io: {
          // Every claim of a numbered revision "loses", and nothing exists to retry against.
          link: (_from, to) => {
            if (/[/\\]\d+\.json$/.test(to)) throw errno('EEXIST');
            return linkSync(_from, to);
          },
        },
        sleep: async () => {
          sleeps += 1;
        },
      })
    ).rejects.toThrow(/too much contention/);
    expect(sleeps).toBe(19);
  });
});

describe('a purge racing a put for the same object', () => {
  async function setup(label: string): Promise<string> {
    const root = await freshStore(label);
    await put(root, signedX); // rev 1: object X
    await put(root, signedY); // rev 2: object Y
    return root;
  }

  function purgeNow(root: string): void {
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    purgeExpired(root, POLICY, FIXTURE_NOW, report.token);
  }

  it.each([
    ['before the put records its transition', 'put:claimed'],
    ['after the put records its transition', 'put:after-append'],
  ])('keeps the object when the purge runs %s', async (_label, step) => {
    const root = await setup(`race-purge-${step.replace(':', '-')}`);
    let purged = false;
    const result = await put(root, signedX, {
      onStep: (name) => {
        if (name === step && !purged) {
          purged = true;
          purgeNow(root);
        }
      },
    });
    expect(purged).toBe(true);
    expect(result.revision).toBe(3);
    expect(sha256(readFileSync(objectPath(root, result.bundleDigest)))).toBe(result.bundleDigest);
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE });
    expect(report.problems).toEqual([]);
  });

  it('puts the object back when the purge condemned it between the write and the check', async () => {
    const root = await setup('race-purge-between');
    const first = readTransitions(root).find((t) => t.revision === 1)?.bundleDigest as string;
    let purged = false;
    await put(root, signedX, {
      onStep: (name) => {
        if (name === 'put:object-written' && !purged) {
          purged = true;
          // Rev 2 is newest, rev 1 purgeable; rev 3 does not exist yet, so nothing vouches for X.
          purgeNow(root);
          expect(existsSync(objectPath(root, first))).toBe(false);
        }
      },
    });
    expect(sha256(readFileSync(objectPath(root, first)))).toBe(first);
  });

  it('restores an object that a surviving revision still names', async () => {
    const root = await freshStore('race-purge-restore');
    await put(root, signedX);
    await put(root, signedX); // rev 2 shares rev 1's object
    purgeNow(root);
    const digest = readTransitions(root)[2].bundleDigest as string;
    expect(existsSync(objectPath(root, digest))).toBe(true);
    expect(readdirSync(join(root, 'objects')).filter((name) => name.startsWith('.condemned'))).toEqual([]);
  });
});

describe('trusting keys concurrently', () => {
  it('lets exactly one of two trusts of the same keyId win', async () => {
    const root = scratch('trust-same');
    await initStore(root, FIXTURE_NOW);
    let inner: Error | undefined;
    expect(() =>
      trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW, {
        onStep: (name) => {
          if (name === 'trust:before-create') {
            try {
              trustKey(root, { keyId: KEY_ID, publicKey: OTHER.publicKey }, FIXTURE_NOW);
            } catch (error) {
              inner = error as Error;
            }
          }
        },
      })
    ).toThrow(/already trusted/);
    expect(inner).toBeUndefined();
    expect(readManifest(root).trustedKeys).toHaveLength(1);
    expect(readdirSync(join(root, 'keys'))).toHaveLength(1);
  });

  it('keeps both of two different keyIds', async () => {
    const root = scratch('trust-diff');
    await initStore(root, FIXTURE_NOW);
    trustKey(root, { keyId: 'a', publicKey }, FIXTURE_NOW, {
      onStep: (name) => {
        if (name === 'trust:before-create') trustKey(root, { keyId: 'b', publicKey: OTHER.publicKey }, FIXTURE_NOW);
      },
    });
    expect(readManifest(root).trustedKeys.map((k) => k.keyId).sort()).toEqual(['a', 'b']);
  });

  it('refuses a keyId already in the frozen manifest list', async () => {
    const root = scratch('trust-frozen');
    mkdirSync(join(root, 'bundles'), { recursive: true });
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({ version: 1, trustedKeys: [{ keyId: KEY_ID, publicKeySpkiDerBase64: spki, addedAt: FIXTURE_NOW }] })
    );
    expect(() => trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW)).toThrow(/already trusted/);
  });
});

describe('two inits', () => {
  it('record a single init line and neither fails', async () => {
    const root = scratch('init-race');
    let nested: Promise<unknown> | undefined;
    await initStore(root, FIXTURE_NOW, {
      onStep: (name) => {
        if (name === 'init:before-manifest') nested = initStore(root, FIXTURE_NOW, { hostname: 'other', pid: 7 });
      },
    });
    await nested;
    expect(readTransitions(root).filter((t) => t.action === 'init')).toHaveLength(1);
    expect(readManifest(root)).toEqual({ version: 2, trustedKeys: [] });
  });
});

describe('createExclusive', () => {
  it('falls back to an exclusive create when the filesystem cannot hard-link', () => {
    const dir = scratch('excl-nolink');
    const runtime = resolveContext({ io: { link: () => { throw errno('ENOTSUP'); } } });
    expect(createExclusive(runtime, join(dir, 'a.json'), Buffer.from('hello'))).toBe(true);
    expect(createExclusive(runtime, join(dir, 'a.json'), Buffer.from('other'))).toBe(false);
    expect(readFileSync(join(dir, 'a.json'), 'utf8')).toBe('hello');
    expect(readdirSync(dir)).toEqual(['a.json']);
  });

  it.each(['EPERM', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV'])('treats %s from link as "cannot link"', (code) => {
    const dir = scratch('excl-code');
    const runtime = resolveContext({ io: { link: () => { throw errno(code); } } });
    expect(createExclusive(runtime, join(dir, 'a.json'), Buffer.from('x'))).toBe(true);
  });

  it('counts an EEXIST with two links on the temp file as a win (lost reply)', () => {
    const dir = scratch('excl-lostreply');
    const runtime = resolveContext({
      io: {
        link: (from, to) => {
          linkSync(from, to);
          throw errno('EEXIST');
        },
      },
    });
    expect(createExclusive(runtime, join(dir, 'a.json'), Buffer.from('mine'))).toBe(true);
    expect(readdirSync(dir)).toEqual(['a.json']);
  });

  it('counts a genuine EEXIST as a loss and leaves the winner untouched', () => {
    const dir = scratch('excl-lost');
    writeFileSync(join(dir, 'a.json'), 'theirs');
    expect(createExclusive(resolveContext(), join(dir, 'a.json'), Buffer.from('mine'))).toBe(false);
    expect(readFileSync(join(dir, 'a.json'), 'utf8')).toBe('theirs');
    expect(readdirSync(dir)).toEqual(['a.json']);
  });

  it('removes its temp file when a step after the write fails', () => {
    const dir = scratch('excl-failed-step');
    const runtime = resolveContext({
      onStep: (name) => {
        if (name === 'create:temp-written') throw errno('EIO');
      },
    });
    expect(() => createExclusive(runtime, join(dir, 'a.json'), Buffer.from('x'))).toThrow(/EIO/);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('keeps the win when removing the temp file fails after the link succeeded', () => {
    const dir = scratch('excl-unlink-fails');
    const runtime = resolveContext({
      io: {
        unlink: (path) => {
          if (path.includes('.tmp-')) throw errno('EIO');
          nodeIO.unlink(path);
        },
      },
    });
    expect(createExclusive(runtime, join(dir, 'a.json'), Buffer.from('mine'))).toBe(true);
    expect(readFileSync(join(dir, 'a.json'), 'utf8')).toBe('mine');
    // The stranded temp is what verify reports, not an error to the winner.
    expect(readdirSync(dir).filter((name) => name.includes('.tmp-'))).toHaveLength(1);
  });

  it('does not let a failing temp cleanup mask the original error', () => {
    const dir = scratch('excl-unlink-masks');
    const runtime = resolveContext({
      io: { unlink: () => { throw errno('EIO'); } },
      onStep: (name) => {
        if (name === 'create:temp-written') throw errno('ENOSPC');
      },
    });
    expect(() => createExclusive(runtime, join(dir, 'a.json'), Buffer.from('x'))).toThrow(/ENOSPC/);
  });

  it('removes a file it created when writing its bytes fails', () => {
    const dir = scratch('excl-open-fail');
    // Not a Buffer: writeSync rejects it after the file has been created.
    const notBytes = { length: 1 } as unknown as Buffer;
    expect(() => nodeIO.openExcl(join(dir, 'a.json'), notBytes)).toThrow();
    expect(readdirSync(dir)).toEqual([]);
  });
});

describe('the exclusive-create fallback', () => {
  it('shows a mid-write reader an incomplete revision, not a crash', async () => {
    const root = await freshStore('fallback-reader');
    const options = { now: FIXTURE_NOW, baseDir: BASE };
    const seen: Record<string, Promise<unknown>> = {};
    const settle = (promise: Promise<unknown>) =>
      promise.then(
        () => 'returned',
        (error: Error) => error.message
      );
    const io = {
      link: () => {
        throw errno('ENOTSUP');
      },
      openExcl: (path: string, bytes: Buffer) => {
        if (path.includes('.tmp-') || !/[/\\]1\.json$/.test(path)) return nodeIO.openExcl(path, bytes);
        const fd = openSync(path, 'wx');
        const half = Math.floor(bytes.length / 2);
        writeSync(fd, bytes.subarray(0, half));
        fsyncSync(fd);
        // Readers start now; each reads the directory and file synchronously
        // before its first await, so they see exactly the half-written state.
        seen.verify = verifyStore(root, options).then((report) => report.problems.join('\n'));
        seen.get = settle(getBundle(root, ENTRY, 1, options));
        seen.newest = settle(getBundle(root, ENTRY, undefined, options));
        writeSync(fd, bytes.subarray(half));
        closeSync(fd);
      },
    };
    const result = await put(root, signedX, { io });
    expect(result.revision).toBe(1);
    expect(await seen.verify).toMatch(/revision 1 is incomplete or unvouched/);
    expect(await seen.verify).not.toMatch(/corrupt/);
    expect(await seen.get).toMatch(/incomplete or unvouched/);
    expect(await seen.newest).toMatch(/no transition vouches/);
    expect((await verifyStore(root, options)).ok).toBe(true);
  });
});

describe('the transition log', () => {
  it('completes a partial write instead of treating it as failure', async () => {
    const root = scratch('partial-write');
    // writeSync may legitimately write fewer bytes than asked; 3 at a time.
    await initStore(root, FIXTURE_NOW, {
      io: { writeSome: (fd, buf, offset, length) => nodeIO.writeSome(fd, buf, offset, Math.min(3, length)) },
    });
    expect(readTransitions(root).map((line) => line.action)).toEqual(['init']);
    expect(readTransitionLog(root).unreadable).toEqual([]);
  });

  it('fails when the bytes cannot be written, and says how far it got', async () => {
    const root = scratch('short-write');
    let calls = 0;
    await expect(
      initStore(root, FIXTURE_NOW, {
        io: { writeSome: (fd, buf, offset) => (calls++ === 0 ? nodeIO.writeSome(fd, buf, offset, 2) : 0) },
      })
    ).rejects.toThrow(/short write.*wrote 2 of/);
  });

  it('fsyncs the per-writer log after the append', async () => {
    const root = scratch('append-fsync');
    const synced: number[] = [];
    await initStore(root, FIXTURE_NOW, {
      io: { fsync: (fd) => { synced.push(fd); nodeIO.fsync(fd); } },
    });
    expect(synced.length).toBeGreaterThan(0);
    const log = readdirSync(join(root, 'transitions.d'))[0];
    expect(readFileSync(join(root, 'transitions.d', log), 'utf8')).toContain('"action":"init"');
  });

  it('parses a new append after a torn last line, and reports the tear', async () => {
    const root = await freshStore('torn');
    const dir = join(root, 'transitions.d');
    const [log] = readdirSync(dir);
    appendFileSync(join(dir, log), '{"at":"2026-09-30T12:00:00Z","act');
    trustKey(root, { keyId: 'second', publicKey: OTHER.publicKey }, FIXTURE_NOW);
    const parsed = readTransitionLog(root);
    expect(parsed.transitions.map((t) => t.action)).toEqual(['init', 'trust', 'trust']);
    expect(parsed.unreadable).toHaveLength(1);
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE });
    expect(report.problems.join('\n')).toMatch(/unreadable transition line/);
  });

  it('merges per-writer logs from two hosts and the legacy log, collapsing identical lines', async () => {
    const root = scratch('hosts');
    await initStore(root, FIXTURE_NOW, { hostname: 'host/A one', pid: 11 });
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW, { hostname: 'hostB', pid: 22 });
    await put(root, signedX, { hostname: 'hostB', pid: 22 });
    const logs = readdirSync(join(root, 'transitions.d'));
    expect(logs).toHaveLength(2);
    expect(logs.find((name) => name.startsWith('host_A_one-11-'))).toBeDefined();
    expect(logs.find((name) => name.startsWith('hostB-22-'))).toBeDefined();
    const legacy = JSON.stringify({ at: FIXTURE_NOW, action: 'trust', detail: `trusted key ${KEY_ID}` });
    writeFileSync(join(root, 'transitions.jsonl'), `${legacy}\n`);
    const actions = readTransitions(root).map((t) => t.action);
    expect(actions.filter((a) => a === 'trust')).toHaveLength(1);
    expect(actions.sort()).toEqual(['init', 'put', 'trust']);
    expect(listEntries(root)[0].bundleDigest).toBeDefined();
  });
});

describe('crashes leave only what verify reports', () => {
  it('does not report a valid entry whose name contains .tmp-', async () => {
    const root = await freshStore('tmp-name');
    await putBundle(root, signedX, { now: FIXTURE_NOW, baseDir: BASE, entry: 'build.tmp-2' });
    await putBundle(root, signedX, { now: FIXTURE_NOW, baseDir: BASE, entry: 'condemned-x.tmp-' });
    expect((await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE })).problems).toEqual([]);
  });

  it('still reports the exact temp and condemned shapes the store produces', async () => {
    const root = await freshStore('tmp-shapes');
    await put(root);
    writeFileSync(join(root, 'bundles', ENTRY, '.2.json.tmp-0123456789abcdef'), 'x');
    writeFileSync(join(root, 'objects', '.condemned-sha256-ab-0123456789abcdef'), 'x');
    const problems = (await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE })).problems.join('\n');
    expect(problems).toMatch(/leftover bundles\/case-exact-in-scope\/\.2\.json\.tmp-0123456789abcdef/);
    expect(problems).toMatch(/leftover objects\/\.condemned-sha256-ab-0123456789abcdef/);
  });

  it('a crash after the temp write leaves a temp file that readers ignore and verify reports', async () => {
    const root = await freshStore('crash-temp');
    await expect(
      put(root, signedX, {
        io: { unlink: () => undefined }, // the process died: no cleanup ran
        onStep: (name) => {
          if (name === 'create:temp-written') throw new Error('crash');
        },
      })
    ).rejects.toThrow(/crash/);
    expect(readdirSync(join(root, 'objects')).some((name) => name.includes('.tmp-'))).toBe(true);
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE });
    expect(report.problems.join('\n')).toMatch(/leftover objects\/.*\.tmp-/);
    expect(listEntries(root)).toEqual([]);
  });

  it('a crash between claiming a revision and recording it is unvouched, and never served as newest', async () => {
    const root = await freshStore('crash-claim');
    await put(root, signedX);
    await expect(
      put(root, signedY, {
        onStep: (name) => {
          if (name === 'put:claimed') throw new Error('crash');
        },
      })
    ).rejects.toThrow(/crash/);
    const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE });
    expect(report.problems.join('\n')).toMatch(/case-exact-in-scope revision 2 has no transition/);
    expect((await getBundle(root, ENTRY, undefined, { now: FIXTURE_NOW, baseDir: BASE })).revision).toBe(1);
    // Revision numbers are never reused: the next put takes 3.
    expect((await put(root, signedY)).revision).toBe(3);
  });

  it('a crash after condemning an object leaves a .condemned file that verify reports', async () => {
    const root = await freshStore('crash-condemned');
    await put(root, signedX);
    await put(root, signedY);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    expect(() =>
      purgeExpired(root, POLICY, FIXTURE_NOW, report.token, {
        onStep: (name) => {
          if (name === 'purge:condemned') throw new Error('crash');
        },
      })
    ).toThrow(/crash/);
    const verified = await verifyStore(root, { now: FIXTURE_NOW, baseDir: BASE });
    expect(verified.problems.join('\n')).toMatch(/leftover objects\/\.condemned-/);
  });

  it('a crash after the purge line but before the unlink is finished by a repeat purge', async () => {
    const root = await freshStore('crash-purge');
    await put(root, signedX);
    await put(root, signedY);
    const report = retentionReport(root, POLICY, FIXTURE_NOW);
    expect(() =>
      purgeExpired(root, POLICY, FIXTURE_NOW, report.token, {
        onStep: (name) => {
          if (name === 'purge:recorded') throw new Error('crash');
        },
      })
    ).toThrow(/crash/);
    expect(revisionFiles(root)).toEqual(['1.json', '2.json']);
    purgeExpired(root, POLICY, FIXTURE_NOW, retentionReport(root, POLICY, FIXTURE_NOW).token);
    expect(revisionFiles(root)).toEqual(['2.json']);
    expect(readTransitions(root).filter((t) => t.action === 'purge')).toHaveLength(1);
  });
});

describe('getBundle without a revision', () => {
  it('returns the newest vouched revision, not the newest file', async () => {
    const root = await freshStore('newest-vouched');
    await put(root, signedX);
    writeFileSync(join(root, 'bundles', ENTRY, '2.json'), readFileSync(join(root, 'bundles', ENTRY, '1.json')));
    const options = { now: FIXTURE_NOW, baseDir: BASE };
    expect((await getBundle(root, ENTRY, undefined, options)).revision).toBe(1);
    expect((await getBundle(root, ENTRY, 2, options)).revision).toBe(2);
  });
});

describe('a version 1 store', () => {
  function v1Store(): { root: string; digest: string } {
    const root = scratch('v1');
    mkdirSync(join(root, 'bundles', ENTRY), { recursive: true });
    mkdirSync(join(root, 'objects'), { recursive: true });
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({ version: 1, trustedKeys: [{ keyId: KEY_ID, publicKeySpkiDerBase64: spki, addedAt: FIXTURE_NOW }] })
    );
    const bytes = `${JSON.stringify(signedX, null, 2)}\n`;
    const digest = sha256(bytes);
    writeFileSync(join(root, 'bundles', ENTRY, '1.json'), bytes);
    writeFileSync(objectPath(root, digest), bytes);
    writeFileSync(
      join(root, 'transitions.jsonl'),
      [
        { at: FIXTURE_NOW, action: 'init' },
        { at: FIXTURE_NOW, action: 'put', entry: ENTRY, revision: 1, bundleDigest: digest },
      ]
        .map((line) => `${JSON.stringify(line)}\n`)
        .join('')
    );
    return { root, digest };
  }

  /** What a pre-lock-free CLI did: readdir every name under bundles/ as an entry directory. */
  function oldListEntries(root: string): string[] {
    const out: string[] = [];
    for (const name of readdirSync(join(root, 'bundles'))) {
      if (existsSync(join(root, 'bundles', name))) out.push(...readdirSync(join(root, 'bundles', name)));
    }
    return out;
  }

  it('is read as it is, then migrated idempotently, and fences old CLIs', async () => {
    const { root, digest } = v1Store();
    const options = { now: FIXTURE_NOW, baseDir: BASE };
    expect(readManifest(root).version).toBe(1);
    expect((await getBundle(root, ENTRY, undefined, options)).revision).toBe(1);
    expect((await verifyStore(root, options)).ok).toBe(true);
    expect(oldListEntries(root)).toEqual(['1.json']);

    await initStore(root, FIXTURE_NOW);
    await initStore(root, FIXTURE_NOW);

    const manifest = readManifest(root);
    expect(manifest.version).toBe(2);
    expect(manifest.trustedKeys.map((k) => k.keyId)).toEqual([KEY_ID]);
    expect(statSync(join(root, 'bundles', '.format-v2')).isFile()).toBe(true);
    expect(statSync(join(root, 'keys')).isDirectory()).toBe(true);
    expect(() => oldListEntries(root)).toThrow(/ENOTDIR/);
    expect(listEntries(root).map((e) => [e.entry, e.revision, e.bundleDigest])).toEqual([[ENTRY, 1, digest]]);
    expect((await verifyStore(root, options)).ok).toBe(true);

    trustKey(root, { keyId: 'later', publicKey: OTHER.publicKey }, FIXTURE_NOW);
    expect(readManifest(root).trustedKeys.map((k) => k.keyId).sort()).toEqual(['later', KEY_ID]);
    expect(readKeyDirectory(root).keys).toHaveLength(1);
    expect((await put(root, signedX)).revision).toBe(2);
  });
});

describe('no lock-free write reaches an unfenced store', () => {
  it('fences a fresh store at init', async () => {
    const root = scratch('fence-fresh');
    await initStore(root, FIXTURE_NOW);
    expect(statSync(join(root, 'bundles', '.format-v2')).isFile()).toBe(true);
  });

  it('migrates a version 1 store before put writes anything', async () => {
    const root = scratch('fence-put');
    mkdirSync(join(root, 'bundles'), { recursive: true });
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({ version: 1, trustedKeys: [{ keyId: KEY_ID, publicKeySpkiDerBase64: spki, addedAt: FIXTURE_NOW }] })
    );
    await put(root, signedX);
    expect(readManifest(root).version).toBe(2);
    expect(statSync(join(root, 'bundles', '.format-v2')).isFile()).toBe(true);
  });

  it('migrates a version 1 store before a key is trusted', () => {
    const root = scratch('fence-trust');
    mkdirSync(join(root, 'bundles'), { recursive: true });
    writeFileSync(join(root, 'manifest.json'), JSON.stringify({ version: 1, trustedKeys: [] }));
    trustKey(root, { keyId: KEY_ID, publicKey }, FIXTURE_NOW);
    expect(statSync(join(root, 'bundles', '.format-v2')).isFile()).toBe(true);
  });
});

