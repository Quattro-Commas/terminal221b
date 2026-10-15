import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { scanLocalWorkspace } from '../src/security.js';

// Lets one test make a chosen file look like it was swapped for a symlink between the
// directory listing and the read; every other read is the real thing.
const swapped = vi.hoisted(() => ({ name: '' }));
vi.mock('../src/bounded-read.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/bounded-read.js')>();
  return {
    ...actual,
    readBoundedFile: (path: string, ...rest: [number, string]) =>
      swapped.name && path.endsWith(swapped.name)
        ? Promise.resolve({ kind: 'skipped', reason: 'symlink' })
        : actual.readBoundedFile(path, ...rest),
  };
});

const directories: string[] = [];

async function makeDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'terminal221b-security-'));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  swapped.name = '';
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe('scanLocalWorkspace', () => {
  it('reports truncated when a candidate is swapped for a symlink during the scan', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'raced.py'), 'print(1)');
    swapped.name = 'raced.py';

    const result = await scanLocalWorkspace(root);

    expect(result.truncated).toBe(true);
    expect(result.filesScanned).toBe(0);
  });

  it('reports high-confidence secret patterns without disclosing their values', async () => {
    const root = await makeDirectory();
    const token = `ghp_${'A'.repeat(36)}`;
    await writeFile(join(root, '.env'), `TOKEN=${token}\n`);

    const result = await scanLocalWorkspace(root);

    expect(result.findings).toEqual([
      expect.objectContaining({
        file: '.env',
        line: 1,
        rule: 'github-token',
        severity: 'high',
      }),
    ]);
    expect(JSON.stringify(result.findings)).not.toContain(token);
  });

  it('skips symlinked files and private key directories', async () => {
    const root = await makeDirectory();
    const outside = await makeDirectory();
    await mkdir(join(root, '.ssh'));
    const shellFlag = 'shell' + '=True';
    await writeFile(join(outside, 'source.py'), `subprocess.run(cmd, ${shellFlag})`);
    await symlink(join(outside, 'source.py'), join(root, 'linked.py'));
    await writeFile(join(root, '.ssh', 'authorized_keys'), 'ssh-key-material');

    const result = await scanLocalWorkspace(root);
    expect(result.findings).toEqual([]);
  });

  it('labels source patterns as review heuristics rather than confirmed vulnerabilities', async () => {
    const root = await makeDirectory();
    const origin = 'tx.' + 'origin';
    await writeFile(
      join(root, 'contract.sol'),
      `function owner() public view returns (address) { return ${origin}; }\n`
    );

    const result = await scanLocalWorkspace(root);
    expect(result.findings).toEqual([
      expect.objectContaining({
        rule: 'solidity-tx-origin',
        severity: 'review',
        message: expect.stringContaining('Heuristic'),
      }),
    ]);
  });
});
