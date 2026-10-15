import { appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, open, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { isWithinRoot, readBoundedFile } from '../src/bounded-read.js';

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

  it('refuses a file reached through a parent swapped for a symlink to another directory inside the root', async () => {
    const root = await makeDirectory();
    await mkdir(join(root, 'b'));
    await writeFile(join(root, 'b', 'x.ts'), 'other file in the workspace');
    // The walker listed root/a/x.ts; root/a has since become a link to root/b.
    await symlink(join(root, 'b'), join(root, 'a'));
    for (const linux of [true, false]) {
      const result = await readBoundedFile(join(root, 'a', 'x.ts'), 100, root, { linux });
      expect(result).toEqual({ kind: 'skipped', reason: 'changed' });
    }
  });

  it.each(['ENOTDIR', 'ELOOP', 'EACCES', 'ENOENT'])(
    'without /proc, maps %s from resolving the opened path to changed',
    async (code) => {
      const root = await makeDirectory();
      await writeFile(join(root, 'a.ts'), 'x');
      const failing = async (): Promise<string> => {
        throw Object.assign(new Error(code), { code });
      };
      expect(await readBoundedFile(join(root, 'a.ts'), 100, root, { linux: false, realpath: failing })).toEqual({
        kind: 'skipped',
        reason: 'changed',
      });
    }
  );

  it('without /proc, still reads a plain file', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'a.ts'), 'x');
    expect(await readBoundedFile(join(root, 'a.ts'), 100, root, { linux: false })).toMatchObject({ kind: 'read' });
  });

  it.each(['EACCES', 'EPERM', 'EAGAIN', 'EWOULDBLOCK'])('skips a file whose open fails with %s as unreadable', async (code) => {
    const root = await makeDirectory();
    await writeFile(join(root, 'a.ts'), 'small');
    const failing = (async () => {
      throw Object.assign(new Error(code), { code });
    }) as unknown as typeof open;
    expect(await readBoundedFile(join(root, 'a.ts'), 100, root, { open: failing })).toEqual({
      kind: 'skipped',
      reason: 'unreadable',
    });
  });

  it('skips a small unreadable file instead of aborting the scan', async () => {
    if (process.getuid?.() === 0) return;
    const root = await makeDirectory();
    await writeFile(join(root, 'locked.ts'), 'small');
    await chmod(join(root, 'locked.ts'), 0o000);
    expect(await readBoundedFile(join(root, 'locked.ts'), 100, root)).toEqual({ kind: 'skipped', reason: 'unreadable' });
  });

  it('skips a file rewritten to the same size while it was read', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'a.ts'), 'abcd');
    // The handle reports a new mtime after the read: same size, different content.
    const rewritten = (async (path: string, flags: number) => {
      const handle = await open(path, flags);
      let stats = 0;
      return {
        fd: handle.fd,
        read: handle.read.bind(handle),
        close: handle.close.bind(handle),
        stat: async (options?: { bigint: true }) => {
          const real = await handle.stat(options ?? { bigint: true });
          stats += 1;
          if (stats === 1) return real;
          // One nanosecond later: the comparison must be finer than milliseconds.
          return Object.assign(Object.create(Object.getPrototypeOf(real)), real, { mtimeNs: real.mtimeNs + 1n });
        },
      };
    }) as unknown as typeof open;
    expect(await readBoundedFile(join(root, 'a.ts'), 100, root, { open: rewritten })).toEqual({
      kind: 'skipped',
      reason: 'changed',
    });
  });

  it('calls a file that grows past the cap while being read changed, not too-large', async () => {
    const root = await makeDirectory();
    const file = join(root, 'edge.ts');
    await writeFile(file, 'x'.repeat(100));
    const growing = (async (path: string, flags: number) => {
      const handle = await open(path, flags);
      let grown = false;
      return {
        fd: handle.fd,
        stat: handle.stat.bind(handle),
        close: handle.close.bind(handle),
        read: async (...args: Parameters<typeof handle.read>) => {
          if (!grown) {
            appendFileSync(file, 'y');
            grown = true;
          }
          return handle.read(...args);
        },
      };
    }) as unknown as typeof open;
    expect(await readBoundedFile(file, 100, root, { open: growing })).toEqual({ kind: 'skipped', reason: 'changed' });
  });

  it('skips a non-file whose open fails with a code Node cannot name (macOS socket)', async () => {
    if (process.platform === 'win32') return;
    const root = await makeDirectory();
    const server = createServer();
    await new Promise<void>((done) => server.listen(join(root, 'sock.ts'), done));
    try {
      // On macOS a socket open fails with errno 102 (EOPNOTSUPP), which libuv does not
      // name; Node reports an "Unknown system error" code. Simulate that code here.
      const failing = (async () => {
        throw Object.assign(new Error('Unknown system error -102'), { code: 'Unknown system error -102' });
      }) as unknown as typeof open;
      expect(await readBoundedFile(join(root, 'sock.ts'), 100, root, { open: failing })).toEqual({
        kind: 'skipped',
        reason: 'not-a-regular-file',
      });
    } finally {
      await new Promise<void>((done) => server.close(() => done()));
    }
  });

  it('still raises an error it does not understand, as readFile did', async () => {
    const root = await makeDirectory();
    await writeFile(join(root, 'a.ts'), 'x');
    const failing = (async () => {
      throw Object.assign(new Error('input/output error'), { code: 'EIO' });
    }) as unknown as typeof open;
    await expect(readBoundedFile(join(root, 'a.ts'), 100, root, { open: failing })).rejects.toThrow('input/output error');
  });
});

describe('isWithinRoot', () => {
  it('accepts descendants, including names that start with two dots', () => {
    expect(isWithinRoot('/r', '/r/a.ts')).toBe(true);
    expect(isWithinRoot('/r', '/r/..cache/a.ts')).toBe(true);
  });

  it('rejects the root itself, its parent and siblings', () => {
    expect(isWithinRoot('/r', '/r')).toBe(false);
    expect(isWithinRoot('/r', '/')).toBe(false);
    expect(isWithinRoot('/r', '/r2/a.ts')).toBe(false);
    expect(isWithinRoot('/r', '/r/../x')).toBe(false);
  });
});
