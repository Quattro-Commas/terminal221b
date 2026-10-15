import { constants } from 'node:fs';
import { lstat, open, readlink, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export type BoundedRead =
  | { kind: 'read'; content: string; bytes: number }
  | {
      kind: 'skipped';
      reason: 'symlink' | 'not-a-regular-file' | 'too-large' | 'outside-root' | 'changed' | 'unreadable';
    };

/** Test seams: the platform probe and the two filesystem calls that are hard to make fail. */
export interface BoundedReadDeps {
  linux?: boolean;
  open?: typeof open;
  realpath?: (path: string) => Promise<string>;
}

// What open(O_NOFOLLOW) reports for a symlink: ELOOP on Linux and macOS, EMLINK on
// FreeBSD, EFTYPE on NetBSD.
// ELOOP also means a looping parent directory; that case is told apart below.
const SYMLINK_OPEN_ERRORS = new Set(['ELOOP', 'EMLINK', 'EFTYPE']);

/**
 * True when `candidate` is strictly inside `root` ("..foo" is a name, not a parent;
 * isAbsolute catches Windows paths on another drive). The root itself is not inside.
 * The one containment predicate shared by readBoundedFile and the scanners.
 */
export function isWithinRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

// Where the opened file really is. On Linux /proc/self/fd/N names the file the
// handle holds, so no later swap of a parent directory can change the answer. Other
// platforms resolve the path again: a narrower check that a precisely timed second
// swap could still pass.
async function openedPath(path: string, fd: number, deps: BoundedReadDeps): Promise<string> {
  if (deps.linux ?? process.platform === 'linux') {
    try {
      return await readlink(`/proc/self/fd/${fd}`);
    } catch {
      // /proc not mounted: fall through to the portable check
    }
  }
  return (deps.realpath ?? realpath)(path);
}

// Errors that mean "this one file changed or cannot be read now", never "stop the scan".
const CHANGED_AFTER_OPEN = new Set(['ENOENT', 'ENOTDIR', 'ELOOP', 'EACCES']);
const UNREADABLE_OPEN_ERRORS = new Set(['EACCES', 'EPERM', 'EAGAIN', 'EWOULDBLOCK']);

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
 *  - the opened file's real path must equal `path` exactly. Callers pass paths built
 *    from the real `root` by a walker that never descends symlinks, so any
 *    difference means a parent directory or the file was swapped (for a link out of
 *    the root, or to another directory inside it) after the listing;
 *  - at most `min(size, maxBytes) + 1` bytes read, so growth after the check is
 *    caught rather than returned as a truncated file;
 *  - the handle is fstat-ed again after the read: a changed size, mtime or ctime
 *    (compared in nanoseconds) means 'changed'. This catches a same-size rewrite only
 *    to the filesystem's timestamp resolution (1 s on HFS+, a coarse tick on older
 *    Linux kernels); a rewrite within one tick is not detectable.
 *
 * The byte budget callers keep counts bytes on disk (`bytes`), not the decoded
 * string length.
 *
 * An unreadable file (permissions, EAGAIN) is skipped as 'unreadable', never an
 * aborted scan. Errors nobody anticipated are still raised.
 *
 * Not covered: the directory walk itself (readdir/visit on a directory swapped for a
 * symlink after it was listed). Only the file read is guarded here; directory
 * traversal is a separate follow-up.
 */
export async function readBoundedFile(
  path: string,
  maxBytes: number,
  root: string,
  deps: BoundedReadDeps = {}
): Promise<BoundedRead> {
  // Nothing can fit: do not open, fstat or readlink a file only to refuse it.
  if (maxBytes < 1) return { kind: 'skipped', reason: 'too-large' };
  let handle;
  try {
    handle = await (deps.open ?? open)(
      path,
      constants.O_RDONLY |
        (constants.O_NOFOLLOW ?? 0) |
        (constants.O_NONBLOCK ?? 0) |
        (constants.O_NOCTTY ?? 0) // a swapped-in tty must never become our controlling terminal
    );
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? '';
    if (SYMLINK_OPEN_ERRORS.has(code)) {
      // Only a symlinked final component is a plain 'symlink'. Anything else (a
      // looping parent) is a candidate that went unread: 'changed', which the
      // scanners report as truncated, never silent.
      const isLink = await lstat(path).then((s) => s.isSymbolicLink(), () => false);
      return { kind: 'skipped', reason: isLink ? 'symlink' : 'changed' };
    }
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      // Deleted, or a parent replaced, between the directory listing and the open.
      return { kind: 'skipped', reason: 'changed' };
    }
    if (code === 'EISDIR' || code === 'ENXIO' || code === 'ENODEV') {
      return { kind: 'skipped', reason: 'not-a-regular-file' }; // directory, socket, device
    }
    if (UNREADABLE_OPEN_ERRORS.has(code)) {
      // An unreadable file over the cap is 'too-large', as under the old size check
      // (which needed no read permission). Look at its size only after the open
      // failed, and never open it again.
      const size = await lstat(path).then((s) => s.size, () => undefined);
      if (size !== undefined && size > maxBytes) return { kind: 'skipped', reason: 'too-large' };
      return { kind: 'skipped', reason: 'unreadable' };
    }
    // Any other failure: if what sits at the path is not a regular file (a socket on
    // macOS fails with errno 102, which libuv cannot even name), skip it; a real error
    // on a regular file still throws. The lstat decides only what to report; nothing
    // is opened after it.
    const kind = await lstat(path).then((s) => (s.isFile() ? 'file' : 'other'), () => 'gone');
    if (kind === 'other') return { kind: 'skipped', reason: 'not-a-regular-file' };
    // Nothing there any more: deleted or a parent swapped between listing and open,
    // the same race ENOENT/ENOTDIR already report as 'changed'.
    if (kind === 'gone') return { kind: 'skipped', reason: 'changed' };
    throw error;
  }
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile()) return { kind: 'skipped', reason: 'not-a-regular-file' };
    if (opened.size > BigInt(maxBytes)) return { kind: 'skipped', reason: 'too-large' };

    try {
      const real = await openedPath(path, handle.fd, deps);
      if (real !== resolve(path)) {
        return { kind: 'skipped', reason: isWithinRoot(root, real) ? 'changed' : 'outside-root' };
      }
    } catch (error) {
      // Deleted, renamed or re-permissioned after the open (an editor's atomic save, a
      // build): that one file changed under us; the scan goes on.
      if (CHANGED_AFTER_OPEN.has((error as NodeJS.ErrnoException).code ?? '')) {
        return { kind: 'skipped', reason: 'changed' };
      }
      throw error;
    }

    const size = Number(opened.size);
    const buffer = Buffer.alloc(Math.min(size, maxBytes) + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const { bytesRead } = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (bytesRead === 0) break;
      bytes += bytesRead;
    }
    // Not what the handle reported: the file grew or shrank while being read, so what
    // is in the buffer is not the file. Checked before any size verdict: a file that
    // grows past the cap mid-read changed; it was not too large when opened.
    if (bytes !== size) return { kind: 'skipped', reason: 'changed' };
    // Same size is not proof: a file truncated and rewritten to the same length during
    // the read leaves old and new pages mixed in the buffer. Any change to the handle's
    // size, mtime or ctime since the first fstat means the bytes are not one file. The
    // times are compared in nanoseconds, so this catches a rewrite to the resolution
    // of the filesystem's own timestamps (1 s on HFS+, a coarse tick on older Linux):
    // a same-size rewrite inside one tick is not detectable here.
    const after = await handle.stat({ bigint: true });
    if (after.size !== opened.size || after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs) {
      return { kind: 'skipped', reason: 'changed' };
    }
    return { kind: 'read', content: buffer.subarray(0, bytes).toString('utf8'), bytes };
  } finally {
    await handle.close();
  }
}
