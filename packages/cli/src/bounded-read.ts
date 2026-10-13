import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

export type BoundedRead =
  | { kind: 'read'; content: string; bytes: number }
  | { kind: 'skipped'; reason: 'symlink' | 'not-a-regular-file' | 'too-large' };

/**
 * Reads one file of a scanned workspace, deciding everything on the open handle.
 *
 * The scanners used to `lstat` a path and then `readFile` the same path. Between
 * the two calls the file could be replaced by a symlink to somewhere outside the
 * workspace, which `readFile` follows, or grow past the size cap. Here the file
 * is opened once with `O_NOFOLLOW` (a symlink fails to open), the size and type
 * come from the handle, and at most `maxBytes + 1` bytes are read from it, so a
 * file that grows after the check is still caught.
 *
 * Errors other than "this is a symlink" are raised, as `readFile` raised them.
 */
export async function readBoundedFile(path: string, maxBytes: number): Promise<BoundedRead> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ELOOP') return { kind: 'skipped', reason: 'symlink' };
    throw error;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) return { kind: 'skipped', reason: 'not-a-regular-file' };
    if (stat.size > maxBytes) return { kind: 'skipped', reason: 'too-large' };

    const buffer = Buffer.alloc(maxBytes + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const { bytesRead } = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (bytesRead === 0) break;
      bytes += bytesRead;
    }
    if (bytes > maxBytes) return { kind: 'skipped', reason: 'too-large' };
    return { kind: 'read', content: buffer.subarray(0, bytes).toString('utf8'), bytes };
  } finally {
    await handle.close();
  }
}
