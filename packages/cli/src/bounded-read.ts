import { constants } from 'node:fs';
import { lstat, open, readlink, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, sep } from 'node:path';

export type BoundedRead =
  | { kind: 'read'; content: string; bytes: number }
  | {
      kind: 'skipped';
      reason: 'symlink' | 'not-a-regular-file' | 'too-large' | 'outside-root' | 'changed';
    };

// What open(O_NOFOLLOW) reports for a symlink: ELOOP on Linux and macOS, EMLINK on
// FreeBSD, EFTYPE on NetBSD.
const SYMLINK_OPEN_ERRORS = new Set(['ELOOP', 'EMLINK', 'EFTYPE']);

// Same rule as the scanners' isWithinRoot ("..foo" is a name, not a parent), plus
// isAbsolute for Windows paths on another drive. The root itself is not a file.
function within(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

// Where the opened file really is. On Linux /proc/self/fd/N names the file the
// handle holds, so no later swap of a parent directory can change the answer. Other
// platforms resolve the path again and compare inodes: a narrower check that a
// precisely timed second swap could still pass.
async function openedPath(path: string, fd: number): Promise<string> {
  if (process.platform === 'linux') {
    try {
      return await readlink(`/proc/self/fd/${fd}`);
    } catch {
      // /proc not mounted: fall through to the portable check
    }
  }
  return realpath(path);
}

/**
 * Reads one file of a scanned workspace so that what is read is provably the file
 * that was walked, inside `root` (which must already be a real path).
 *
 * The scanners used to `lstat` a path and then `readFile` it. Between the two calls
 * the file, or one of its parent directories, could be replaced by a symlink to
 * somewhere outside the workspace, or the file could grow past the cap. Here:
 *  - no check before the open (a check-then-open is the race this replaces); an
 *    unreadable file over the cap is still skipped, not an error, as under the old
 *    `lstat` size check, by looking at its size only after the open failed;
 *  - one `open` with `O_NOFOLLOW` (a symlinked file fails to open) and `O_NONBLOCK`
 *    (a file swapped for a FIFO cannot hang the scan);
 *  - type and size taken from the handle;
 *  - the opened file must resolve inside `root` and be the same file (device and
 *    inode) as the real path: a swapped parent directory, or a symlink on a
 *    platform without `O_NOFOLLOW`, is refused here;
 *  - at most `min(size, maxBytes) + 1` bytes read, so growth after the check is
 *    caught rather than returned as a truncated file.
 *
 * Errors other than "this is a symlink" are raised, as `readFile` raised them.
 */
export async function readBoundedFile(path: string, maxBytes: number, root: string): Promise<BoundedRead> {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)
    );
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? '';
    if (SYMLINK_OPEN_ERRORS.has(code)) return { kind: 'skipped', reason: 'symlink' };
    if (code === 'EISDIR' || code === 'ENXIO' || code === 'ENODEV') {
      return { kind: 'skipped', reason: 'not-a-regular-file' }; // directory, socket, device
    }
    if (code === 'EACCES' || code === 'EPERM') {
      // The old size check needed no read permission, so an unreadable file over the
      // cap was skipped, not an error. Keep that: look at its size only after the open
      // failed, and never open it again.
      const size = await lstat(path).then((s) => s.size, () => undefined);
      if (size !== undefined && size > maxBytes) return { kind: 'skipped', reason: 'too-large' };
    }
    throw error;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) return { kind: 'skipped', reason: 'not-a-regular-file' };
    if (opened.size > maxBytes) return { kind: 'skipped', reason: 'too-large' };

    try {
      const real = await openedPath(path, handle.fd);
      if (!within(root, real)) return { kind: 'skipped', reason: 'outside-root' };
      const atReal = await stat(real);
      if (atReal.dev !== opened.dev || atReal.ino !== opened.ino) {
        return { kind: 'skipped', reason: 'changed' };
      }
    } catch (error) {
      // Deleted or renamed after the open (an editor's atomic save, a build): that
      // one file changed under us; the scan goes on.
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'skipped', reason: 'changed' };
      throw error;
    }

    const buffer = Buffer.alloc(Math.min(opened.size, maxBytes) + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const { bytesRead } = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (bytesRead === 0) break;
      bytes += bytesRead;
    }
    if (bytes > maxBytes) return { kind: 'skipped', reason: 'too-large' };
    // Not what the handle reported: the file grew or shrank while being read, so what
    // is in the buffer is not the file.
    if (bytes !== opened.size) return { kind: 'skipped', reason: 'changed' };
    return { kind: 'read', content: buffer.subarray(0, bytes).toString('utf8'), bytes };
  } finally {
    await handle.close();
  }
}
