/**
 * The filesystem seam under the case store.
 *
 * Every mutation the store makes goes through a `StoreIO`, and every point
 * where two writers could interleave announces itself through `onStep`. That
 * makes the races the store is designed around reproducible: a test installs a
 * hook that performs the competing write at exactly the step under test, instead
 * of hoping a stress run lands there. Production code passes no context and gets
 * `node:fs`.
 *
 * This module is internal to the package. Tests import it directly; nothing in
 * the CLI's public surface re-exports it.
 */
import { randomBytes } from 'node:crypto';
import {
  closeSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { hostname as osHostname } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';

export interface FileStat {
  dev: number;
  ino: number;
  nlink: number;
  size: number;
}

export interface StoreIO {
  link(existing: string, created: string): void;
  /**
   * Create `path`, which must not exist, write `bytes`, fsync, close. If the
   * write fails after the file was created, the file is removed again: the
   * caller never has to wonder whether a half-written file is theirs.
   */
  openExcl(path: string, bytes: Buffer): void;
  rename(from: string, to: string): void;
  unlink(path: string): void;
  /** Opens `path` for appending (`create` makes it exclusive) and returns the fd. */
  openAppend(path: string, create: boolean): number;
  /** One `writeSync`; may write fewer bytes than asked. Returns the bytes written. */
  writeSome(fd: number, buffer: Buffer, offset: number, length: number): number;
  fsync(fd: number): void;
  close(fd: number): void;
  readdir(path: string): string[];
  readFile(path: string): Buffer;
  stat(path: string): FileStat;
}

export const nodeIO: StoreIO = {
  link: (existing, created) => linkSync(existing, created),
  openExcl(path, bytes) {
    const fd = openSync(path, 'wx');
    try {
      writeAll(fd, bytes);
      fsyncSync(fd);
    } catch (error) {
      closeSync(fd);
      unlinkSync(path);
      throw error;
    }
    closeSync(fd);
  },
  rename: (from, to) => renameSync(from, to),
  unlink: (path) => unlinkSync(path),
  openAppend: (path, create) => openSync(path, create ? 'ax' : 'a'),
  writeSome: (fd, buffer, offset, length) => writeSync(fd, buffer, offset, length),
  fsync: (fd) => fsyncSync(fd),
  close: (fd) => closeSync(fd),
  readdir: (path) => readdirSync(path),
  readFile: (path) => readFileSync(path),
  stat(path) {
    const { dev, ino, nlink, size } = statSync(path);
    return { dev, ino, nlink, size };
  },
};

function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(fd, bytes, offset, bytes.length - offset);
}

export interface StoreContext {
  io?: Partial<StoreIO>;
  /**
   * Called at every named step where another writer could interleave. `put`
   * awaits it; the synchronous operations (init, trust, purge) do not, so a hook
   * installed on those must itself be synchronous.
   */
  onStep?: (name: string) => void | Promise<void>;
  /** Identity of the writer for its transition log. Defaults to this host and process. */
  hostname?: string;
  pid?: number;
  sleep?: (ms: number) => Promise<void>;
  randomHex?: (bytes: number) => string;
}

export interface StoreRuntime {
  io: StoreIO;
  step(name: string): void | Promise<void>;
  hostname: string;
  pid: number;
  sleep(ms: number): Promise<void>;
  randomHex(bytes: number): string;
}

export function resolveContext(context?: StoreContext): StoreRuntime {
  return {
    io: { ...nodeIO, ...context?.io },
    step: (name) => context?.onStep?.(name),
    hostname: context?.hostname ?? osHostname(),
    pid: context?.pid ?? process.pid,
    sleep: context?.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms))),
    randomHex: context?.randomHex ?? ((bytes) => randomBytes(bytes).toString('hex')),
  };
}

export function errnoCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

/* -------------------------------------------------------------------------- */
/* Durable writes                                                               */
/* -------------------------------------------------------------------------- */

export function fsyncDir(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    fsyncSync(fd);
  } catch {
    // A directory that cannot be opened for reading cannot be fsynced; the
    // link or rename that preceded this is still atomic, so the write is safe
    // without it.
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Temp names carry random bits: a pid alone collides across hosts sharing a mount. */
function tempNameFor(runtime: StoreRuntime, target: string): string {
  return join(dirname(target), `.${basename(target)}.tmp-${runtime.randomHex(8)}`);
}

function removeIfPresent(io: StoreIO, path: string): void {
  try {
    io.unlink(path);
  } catch (error) {
    if (errnoCode(error) !== 'ENOENT') throw error;
  }
}

/**
 * temp file -> fsync -> rename -> fsync parent. The rename is the atomic step,
 * so a reader never observes a half-written file. It REPLACES whatever is
 * there, so it is for last-writer-wins files and for repairs, never for claiming
 * a name: use `createExclusive` for that.
 */
export function writeDurable(runtime: StoreRuntime, path: string, bytes: Buffer | string): void {
  const target = resolve(path);
  const parent = dirname(target);
  mkdirSync(parent, { recursive: true });
  const temp = tempNameFor(runtime, target);
  try {
    runtime.io.openExcl(temp, Buffer.from(bytes));
    runtime.io.rename(temp, target);
  } catch (error) {
    // Best effort: a failed cleanup must not replace the error that got us here.
    // A stranded temp is a leftover that verify reports.
    try {
      removeIfPresent(runtime.io, temp);
    } catch {
      // see above
    }
    throw error;
  }
  fsyncDir(parent);
}

/** Errors from link(2) that mean "this filesystem cannot hard-link", not "someone else won". */
const LINK_UNSUPPORTED = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV']);

/**
 * Creates `final` with `bytes` if and only if it does not exist, and says
 * whether this call is the one that created it.
 *
 * The bytes are written to a private temp file in the same directory and then
 * hard-linked to the final name. link(2) is atomic and fails with EEXIST rather
 * than replacing, and a reader sees either no file or the complete one. Nothing
 * here claims a name by rename, which silently replaces.
 *
 * If link(2) reports EEXIST but the temp file has two links (or shares the
 * final file's inode), the link succeeded and only the reply was lost, as can
 * happen over NFS: that is a win, not a loss.
 *
 * On a filesystem that cannot hard-link, the fallback is an exclusive create of
 * the final name. That is still exclusive, but a concurrent reader may observe
 * a partially written file; readers treat an unparseable revision with no
 * transition as incomplete rather than corrupt for exactly this reason.
 */
export function createExclusive(runtime: StoreRuntime, final: string, bytes: Buffer): boolean {
  const target = resolve(final);
  const dir = dirname(target);
  const temp = tempNameFor(runtime, target);
  let won = false;
  try {
    runtime.io.openExcl(temp, bytes);
    runtime.step('create:temp-written');
    try {
      runtime.io.link(temp, target);
      won = true;
    } catch (error) {
      const code = errnoCode(error);
      if (code === 'EEXIST') {
        won = linkSurvived(runtime.io, temp, target);
      } else if (code !== undefined && LINK_UNSUPPORTED.has(code)) {
        won = createWithoutLink(runtime.io, target, bytes);
      } else {
        throw error;
      }
    }
    runtime.step('create:linked');
  } finally {
    // The temp is only scaffolding. Once the link succeeded the claim is made,
    // and an unlink failure here must neither undo it nor mask the error that
    // got us here; a stranded temp is a leftover that verify reports.
    try {
      removeIfPresent(runtime.io, temp);
    } catch {
      // see above
    }
  }
  if (won) fsyncDir(dir);
  return won;
}

function linkSurvived(io: StoreIO, temp: string, target: string): boolean {
  const ours = io.stat(temp);
  if (ours.nlink === 2) return true;
  try {
    const theirs = io.stat(target);
    return theirs.ino === ours.ino && theirs.dev === ours.dev;
  } catch (error) {
    if (errnoCode(error) === 'ENOENT') return false;
    throw error;
  }
}

function createWithoutLink(io: StoreIO, target: string, bytes: Buffer): boolean {
  try {
    io.openExcl(target, bytes);
    return true;
  } catch (error) {
    if (errnoCode(error) === 'EEXIST') return false;
    throw error;
  }
}

/* -------------------------------------------------------------------------- */
/* Append                                                                       */
/* -------------------------------------------------------------------------- */

/** A leading newline closes any torn line a crashed predecessor left behind. */
export function frameLine(json: string): Buffer {
  return Buffer.from(`\n${json}\n`, 'utf8');
}

/**
 * Appends `line` completely and fsyncs. `writeSync` may write fewer bytes than
 * asked without anything being wrong, so this loops until everything is out and
 * fails only when a write makes no progress (or errors). A crash part-way still
 * leaves at most a torn last line, which the next record's leading newline and
 * the tolerant reader absorb.
 */
export function appendWhole(runtime: StoreRuntime, path: string, line: Buffer, create: boolean): void {
  const { io } = runtime;
  const fd = io.openAppend(path, create);
  try {
    let written = 0;
    while (written < line.length) {
      const n = io.writeSome(fd, line, written, line.length - written);
      if (n <= 0) {
        throw new Error(`short write appending to ${path}: wrote ${written} of ${line.length} bytes`);
      }
      written += n;
    }
    io.fsync(fd);
  } finally {
    io.close(fd);
  }
}
