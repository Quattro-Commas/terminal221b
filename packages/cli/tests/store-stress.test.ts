import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { FIXTURE_NOW, fixtureBundle } from '../src/case-fixtures.js';
import { initStore, readTransitions, signBundle, trustKey, verifyStore } from '../src/store.js';

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = resolve(here, '..', 'src');
const WORKERS = 4;
const PUTS_EACH = 25;

/** Transpiles the store and what it imports into a temp dir so plain `node` can run it. */
function compileStore(): string {
  const out = mkdtempSync(join(tmpdir(), 't221b-compiled-'));
  writeFileSync(join(out, 'package.json'), '{"type":"module"}\n');
  const queue = ['store.ts', 'case.ts'];
  const done = new Set<string>();
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (done.has(file)) continue;
    done.add(file);
    const source = readFileSync(join(srcDir, file), 'utf8');
    for (const match of source.matchAll(/from '\.\/([\w-]+)\.js'/g)) queue.push(`${match[1]}.ts`);
    const js = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText;
    writeFileSync(join(out, file.replace(/\.ts$/, '.js')), js);
  }
  return out;
}

describe.skipIf(process.platform === 'win32')('concurrent writers in separate processes', () => {
  it(
    `${WORKERS} processes x ${PUTS_EACH} puts give unique, contiguous, vouched revisions`,
    async () => {
      const compiled = compileStore();
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const root = mkdtempSync(join(tmpdir(), 't221b-stress-'));
      const base = mkdtempSync(join(tmpdir(), 't221b-stress-src-'));
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
      await initStore(root, FIXTURE_NOW);
      trustKey(root, { keyId: 'k', publicKey }, FIXTURE_NOW);
      const bundlePath = join(base, 'bundle.json');
      writeFileSync(bundlePath, JSON.stringify(signBundle(fixtureBundle, privateKey, 'k', FIXTURE_NOW)));

      const worker = join(here, 'helpers', 'store-stress-worker.mjs');
      const runs = Array.from({ length: WORKERS }, () =>
        new Promise<number[]>((done, fail) => {
          const child = spawn(
            process.execPath,
            [worker, compiled, root, bundlePath, base, String(PUTS_EACH)],
            { stdio: ['ignore', 'pipe', 'pipe'] }
          );
          let stdout = '';
          let stderr = '';
          child.stdout.on('data', (chunk) => (stdout += chunk));
          child.stderr.on('data', (chunk) => (stderr += chunk));
          child.on('error', fail);
          child.on('close', (code) =>
            code === 0 ? done(JSON.parse(stdout) as number[]) : fail(new Error(`worker exited ${code}: ${stderr}`))
          );
        })
      );
      const claimed = (await Promise.all(runs)).flat().sort((a, b) => a - b);
      const total = WORKERS * PUTS_EACH;
      expect(claimed).toEqual(Array.from({ length: total }, (_, i) => i + 1));

      const entryDir = join(root, 'bundles', 'case-exact-in-scope');
      expect(readdirSync(entryDir).sort((a, b) => parseInt(a) - parseInt(b))).toEqual(
        claimed.map((n) => `${n}.json`).sort((a, b) => parseInt(a) - parseInt(b))
      );
      const vouched = readTransitions(root).filter((t) => t.action === 'put').map((t) => t.revision);
      expect(vouched.sort((a, b) => (a as number) - (b as number))).toEqual(claimed);
      expect(readdirSync(join(root, 'transitions.d')).length).toBeGreaterThanOrEqual(WORKERS);
      expect(existsSync(join(root, '.lock'))).toBe(false);
      const report = await verifyStore(root, { now: FIXTURE_NOW, baseDir: base });
      expect(report.problems).toEqual([]);
    },
    60_000
  );
});
