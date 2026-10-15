import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readBoundedFile } from '../src/bounded-read.js';

const temporaryDirectories: string[] = [];

async function makeDirectory(): Promise<string> {
  // realpath: the scanners pass a real root, and tmpdir() is itself a symlink on macOS.
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'terminal221b-bounded-')));
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
    expect(await readBoundedFile(join(root, 'a.ts'), 100, root)).toEqual({
      kind: 'read',
      content: 'export const a = 1;',
      bytes: 19,
    });
  });

  it('does not follow a symlinked file, so its target is never returned', async () => {
    const root = await makeDirectory();
    const outside = await makeDirectory();
    await writeFile(join(outside, 'secret.txt'), 'outside the workspace');
    await symlink(join(outside, 'secret.txt'), join(root, 'swapped.ts'));
    const result = await readBoundedFile(join(root, 'swapped.ts'), 100, root);
    expect(result).toEqual({ kind: 'skipped', reason: 'symlink' });
    expect(JSON.stringify(result)).not.toContain('outside the workspace');
  });

  it('refuses a file reached through a parent directory swapped for a symlink', async () => {
    const root = await makeDirectory();
    const outside = await makeDirectory();
    await writeFile(join(outside, 'a.ts'), 'outside the workspace');
    // What a walker sees after src/ was replaced by a link to somewhere else.
    await symlink(outside, join(root, 'src'));
    const result = await readBoundedFile(join(root, 'src', 'a.ts'), 100, root);
    expect(result).toEqual({ kind: 'skipped', reason: 'outside-root' });
    expect(JSON.stringify(result)).not.toContain('outside the workspace');
  });

  it('skips a file larger than the limit without returning any of it', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'big.ts'), 'x'.repeat(101));
    expect(await readBoundedFile(join(root, 'big.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'too-large' });
  });

  it('accepts a file of exactly the limit', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'edge.ts'), 'x'.repeat(100));
    expect(await readBoundedFile(join(root, 'edge.ts'), 100, root)).toMatchObject({ kind: 'read', bytes: 100 });
  });

  it('still skips an unreadable file that is over the limit, as the old size check did', async () => {
    if (process.getuid?.() === 0) return; // root reads anything
    const root = await makeDirectory();
    await writeFile(join(root, 'locked.ts'), 'x'.repeat(101));
    await chmod(join(root, 'locked.ts'), 0o000);
    expect(await readBoundedFile(join(root, 'locked.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'too-large' });
  });

  it('skips a FIFO without blocking on it', async () => {
    if (process.platform === 'win32') return;
    const root = await makeDirectory();
    execFileSync('mkfifo', [join(root, 'pipe.ts')]);
    expect(await readBoundedFile(join(root, 'pipe.ts'), 100, root)).toEqual({
      kind: 'skipped',
      reason: 'not-a-regular-file',
    });
  });

  it('counts bytes on disk, not the length of the decoded text', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'latin1.ts'), Buffer.from([0x63, 0xe9, 0xe8, 0x0a])); // invalid UTF-8
    expect(await readBoundedFile(join(root, 'latin1.ts'), 100, root)).toMatchObject({ kind: 'read', bytes: 4 });
  });

  it('skips something that is not a regular file', async () => {
    const root = await makeDirectory();
    await mkdir(join(root, 'dir.ts'));
    expect(await readBoundedFile(join(root, 'dir.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'not-a-regular-file' });
  });

  it('reads a file whose name starts with two dots: it is inside the root', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, '..cache.ts'), 'export const c = 1;');
    expect(await readBoundedFile(join(root, '..cache.ts'), 100, root)).toMatchObject({ kind: 'read', bytes: 19 });
  });

  it('skips a socket instead of aborting the scan', async () => {
    if (process.platform === 'win32') return;
    const root = await makeDirectory();
    const server = createServer();
    await new Promise<void>((done) => server.listen(join(root, 'sock.ts'), done));
    try {
      expect(await readBoundedFile(join(root, 'sock.ts'), 100, root)).toEqual({
        kind: 'skipped',
        reason: 'not-a-regular-file',
      });
    } finally {
      await new Promise<void>((done) => server.close(() => done()));
    }
  });

  it('skips a file deleted between the listing and the open instead of aborting the scan', async () => {
    const root = await makeDirectory();
    expect(await readBoundedFile(join(root, 'gone.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'changed' });
  });

  it('skips a file whose parent was replaced by a plain file (ENOTDIR)', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'src'), 'now a file');
    expect(await readBoundedFile(join(root, 'src', 'a.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'changed' });
  });

  it('reports a looping parent directory as changed, not as a symlinked file', async () => {
    if (process.platform === 'win32') return;
    const root = await makeDirectory();
    await symlink(join(root, 'loop'), join(root, 'loop'));
    expect(await readBoundedFile(join(root, 'loop', 'a.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'changed' });
  });

  it('does not open anything when no bytes are left', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'a.ts'), '');
    expect(await readBoundedFile(join(root, 'a.ts'), 0, root)).toEqual({ kind: 'skipped', reason: 'too-large' });
  });

  it('still raises an error it does not understand, as readFile did', async () => {
    const root = await makeDirectory();
    await mkdir(join(root, 'dir'));
    await chmod(join(root, 'dir'), 0o000);
    try {
      if (process.getuid?.() === 0) return; // root ignores the mode
      await expect(readBoundedFile(join(root, 'dir', 'a.ts'), 100, root)).rejects.toThrow();
    } finally {
      await chmod(join(root, 'dir'), 0o755);
    }
  });
});
