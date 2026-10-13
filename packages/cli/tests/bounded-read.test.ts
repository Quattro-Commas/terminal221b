import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readBoundedFile } from '../src/bounded-read.js';

const temporaryDirectories: string[] = [];

async function makeDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'terminal221b-bounded-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))
  );
});

describe('readBoundedFile', () => {
  it('reads a regular file within the limit', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'a.ts'), 'export const a = 1;');
    expect(await readBoundedFile(join(root, 'a.ts'), 100)).toEqual({
      kind: 'read',
      content: 'export const a = 1;',
      bytes: 19,
    });
  });

  it('does not follow a symlink, so a file swapped for one cannot leak what it points at', async () => {
    const root = await makeDirectory();
    const outside = await makeDirectory();
    await writeFile(join(outside, 'secret.txt'), 'outside the workspace');
    await symlink(join(outside, 'secret.txt'), join(root, 'swapped.ts'));
    const result = await readBoundedFile(join(root, 'swapped.ts'), 100);
    expect(result).toEqual({ kind: 'skipped', reason: 'symlink' });
    expect(JSON.stringify(result)).not.toContain('outside the workspace');
  });

  it('skips a file larger than the limit without returning any of it', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'big.ts'), 'x'.repeat(101));
    expect(await readBoundedFile(join(root, 'big.ts'), 100)).toEqual({ kind: 'skipped', reason: 'too-large' });
  });

  it('accepts a file of exactly the limit', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'edge.ts'), 'x'.repeat(100));
    expect(await readBoundedFile(join(root, 'edge.ts'), 100)).toMatchObject({ kind: 'read', bytes: 100 });
  });

  it('skips something that is not a regular file', async () => {
    const root = await makeDirectory();
    expect(await readBoundedFile(root, 100)).toEqual({ kind: 'skipped', reason: 'not-a-regular-file' });
  });

  it('still raises an error it does not understand, as readFile did', async () => {
    const root = await makeDirectory();
    await expect(readBoundedFile(join(root, 'missing.ts'), 100)).rejects.toThrow();
  });
});
