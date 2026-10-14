/**
 * The local case store: a directory on this machine that holds accepted case
 * bundles, the public keys their operator signatures are checked against, and an
 * append-only transition log.
 *
 * Three rules the store exists to enforce, and the reason each one cannot live
 * in the schema layer:
 *
 * 1. A bundle's declared content digests are recomputed from the bytes on disk
 *    (F5). A bundle is a local JSON file, so a declared digest is a claim; only
 *    hashing the actual file turns it into a check.
 * 2. A record that asserts a human decided something carries a detached
 *    signature, and the store refuses to accept an unsigned one (F4). The
 *    public keys live in the manifest; the private key never enters a bundle
 *    and is never written here.
 * 3. Remote sources are never fetched. An `https://` source is recorded as
 *    unverifiable-here and left alone, because a store whose integrity check
 *    performs network egress is not a local store.
 */
import {
  createHash,
  createPrivateKey,
  randomBytes,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  KeyObject,
} from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ApprovalRecord,
  Attestation,
  CaseBundle,
  ConfirmationRecord,
  parseCaseBundle,
  RETENTION_CLASSES,
  validateCaseBundle,
} from './case.js';

const SCHEMA_VERSION = 1;
/** Bumping this changes what a signature commits to, so old signatures stop verifying. */
export const SIGNATURE_CONTEXT = 'terminal221b/record-signature/v1';

export interface TrustedKey {
  keyId: string;
  publicKeySpkiDerBase64: string;
  label?: string;
  addedAt: string;
}

export interface StoreManifest {
  version: number;
  trustedKeys: TrustedKey[];
}

export interface StoreEntry {
  entry: string;
  revision: number;
  /**
   * The digest the store recorded when the revision was written, taken from
   * the transition log. Deliberately NOT recomputed from the file on disk: a
   * digest derived from the bytes under test compares equal to itself, which
   * would make the integrity check pass by construction. `undefined` means the
   * transition log has no line for this revision, so nothing vouches for the
   * bytes at all.
   */
  bundleDigest?: string;
  storedAt: string;
}

export interface SourceVerification {
  sourceId: string;
  uri: string;
  status: 'verified' | 'unverifiable-here' | 'mismatch' | 'missing';
  declaredDigest: string;
  actualDigest?: string;
}

export interface PutResult {
  entry: string;
  revision: number;
  bundleDigest: string;
  storedAt: string;
  sources: SourceVerification[];
}

export interface VerifyReport {
  ok: boolean;
  problems: string[];
  entries: StoreEntry[];
  sources: SourceVerification[];
  signatures: SignatureReport[];
}

export interface SignatureReport {
  recordKind: AttestedKind;
  recordId: string;
  status: 'signed' | 'unsigned' | 'unknown-key' | 'bad-signature' | 'digest-mismatch';
  keyId?: string;
}

export type AttestedKind =
  | 'approval'
  | 'outcome'
  | 'confirmation'
  | 'duplicateSearch'
  | 'assessment';

export interface AttestedRecord {
  version: 1;
  attestation?: Attestation;
}

const ID_FIELD: Record<AttestedKind, string> = {
  approval: 'approvalId',
  outcome: 'outcomeId',
  confirmation: 'confirmationId',
  duplicateSearch: 'searchId',
  assessment: 'assessmentId',
};

const BUNDLE_FIELD: Record<AttestedKind, keyof CaseBundle> = {
  approval: 'approvals',
  outcome: 'outcomes',
  confirmation: 'confirmations',
  duplicateSearch: 'duplicateSearches',
  assessment: 'assessments',
};

export const ATTESTED_KINDS: readonly AttestedKind[] = [
  'approval',
  'outcome',
  'confirmation',
  'duplicateSearch',
  'assessment',
];

export function recordsOfKind(bundle: CaseBundle, kind: AttestedKind): AttestedRecord[] {
  return bundle[BUNDLE_FIELD[kind]] as unknown as AttestedRecord[];
}

export function recordIdOf(record: AttestedRecord, kind: AttestedKind): string {
  const id = (record as unknown as Record<string, unknown>)[ID_FIELD[kind]];
  if (typeof id !== 'string' || !id) {
    throw new Error(`${kind} record has no ${ID_FIELD[kind]}`);
  }
  return id;
}

/* -------------------------------------------------------------------------- */
/* Store location and layout                                                    */
/* -------------------------------------------------------------------------- */

export interface StorePaths {
  root: string;
  manifest: string;
  bundles: string;
  objects: string;
  transitions: string;
  lock: string;
}

/**
 * Defaults outside any repository so that storing a case never dirties a git
 * status, and so a bundle written to a shared checkout cannot be mistaken for
 * operator state.
 */
export function defaultStoreRoot(): string {
  const dataHome = process.env.XDG_DATA_HOME;
  if (dataHome && isAbsolute(dataHome)) {
    return join(dataHome, 'terminal221b');
  }
  return join(homedir(), '.local', 'share', 'terminal221b');
}

export function resolveStoreRoot(explicit?: string): string {
  if (explicit !== undefined && explicit.trim() === '') {
    throw new Error('--store requires a directory path');
  }
  return resolve(explicit !== undefined ? explicit : defaultStoreRoot());
}

export function storePaths(root: string): StorePaths {
  const at = resolve(root);
  return {
    root: at,
    manifest: join(at, 'manifest.json'),
    bundles: join(at, 'bundles'),
    objects: join(at, 'objects'),
    transitions: join(at, 'transitions.jsonl'),
    lock: join(at, '.lock'),
  };
}

/* -------------------------------------------------------------------------- */
/* Durable writes                                                               */
/* -------------------------------------------------------------------------- */

function fsyncDir(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    fsyncSync(fd);
  } catch {
    // A directory that cannot be opened for reading cannot be fsynced; the
    // rename below is still atomic, so the write is safe without this.
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * temp file -> fsync -> rename -> fsync parent. The rename is the atomic step,
 * so a reader never observes a half-written bundle or manifest.
 */
function writeDurable(path: string, bytes: Buffer | string): void {
  const target = resolve(path);
  const parent = dirname(target);
  mkdirSync(parent, { recursive: true });
  const temp = join(parent, `.${basenameOf(target)}.tmp-${process.pid}`);
  const fd = openSync(temp, 'w');
  try {
    if (Buffer.isBuffer(bytes)) writeSync(fd, bytes);
    else writeSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temp, target);
  fsyncDir(parent);
}

function basenameOf(path: string): string {
  const parts = resolve(path).split(sep);
  return parts[parts.length - 1];
}

/**
 * A cooperative lock: advisory, taken by linking a file holding our pid and a
 * random token into place, released only by its holder. Two concurrent `put`s in
 * the same store would otherwise both compute the next revision from the same
 * on-disk state and one would overwrite the other.
 */
export function withStoreLock<T>(paths: StorePaths, body: () => T): T {
  mkdirSync(paths.root, { recursive: true });
  const token = takeLock(paths.lock);
  try {
    return body();
  } finally {
    releaseLock(paths.lock, token);
  }
}

const LOCK_ATTEMPTS = 5;

/**
 * Takes the lock and returns the token that proves we hold it.
 *
 * The lock file appears atomically and already complete: the token is written to a
 * private temp file which is then hard-linked to the lock path, so `link` either
 * creates the lock with our token in it or fails with EEXIST. (Creating the file
 * and then writing the pid let another process read an empty lock and take it
 * over as stale while its holder was alive.)
 *
 * A lock whose holder is gone is moved aside under a unique name, and deleted only
 * if what was moved is still the dead holder's lock; if a live lock was moved by
 * mistake it is linked back. What is left is a narrow race that needs a stale lock
 * and three processes at once; release still never deletes a lock it does not own.
 */
function takeLock(lock: string): string {
  const token = `${process.pid}:${randomBytes(8).toString('hex')}`;
  const temp = `${lock}.${token.replace(':', '-')}.tmp`;
  writeFileSync(temp, `${token}\n`, { flag: 'wx' });
  try {
    for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
      try {
        linkSync(temp, lock);
        return token;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      const holder = readLockHolder(lock);
      if (holder === undefined) continue; // released meanwhile: try again
      if (holderIsAlive(holder)) {
        throw new Error(`the case store is locked by process ${holder.split(':')[0] || holder}`);
      }
      removeStaleLock(lock, holder, token);
    }
    throw new Error('the case store lock could not be taken: it kept changing hands');
  } finally {
    rmSync(temp, { force: true });
  }
}

function releaseLock(lock: string, token: string): void {
  // Only our own lock: if it was taken over, deleting it would free someone else's.
  if (readLockHolder(lock) === token) rmSync(lock, { force: true });
}

function readLockHolder(lock: string): string | undefined {
  try {
    return readFileSync(lock, 'utf8').trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

function holderIsAlive(holder: string): boolean {
  const pid = /^(\d+)(?::|$)/.exec(holder)?.[1];
  return pid !== undefined && isProcessAlive(Number(pid));
}

function removeStaleLock(lock: string, staleHolder: string, token: string): void {
  const aside = `${lock}.stale-${token.replace(':', '-')}`;
  try {
    renameSync(lock, aside);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; // someone else moved it
    throw error;
  }
  if (readLockHolder(aside) === staleHolder) {
    rmSync(aside, { force: true });
    return;
  }
  // We moved a lock that is not the stale one we read: put it back.
  try {
    linkSync(aside, lock);
  } catch {
    // The slot was taken again meanwhile; leave it to its owner's release check,
    // which will find the lock is no longer theirs.
  }
  rmSync(aside, { force: true });
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: the process exists but belongs to another user. Only ESRCH means gone.
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/* -------------------------------------------------------------------------- */
/* Manifest                                                                     */
/* -------------------------------------------------------------------------- */

export async function initStore(root: string, now: string): Promise<StorePaths> {
  const paths = storePaths(root);
  mkdirSync(paths.bundles, { recursive: true });
  mkdirSync(paths.objects, { recursive: true });
  // Append mode creates the file if it is missing and never truncates it, with no
  // exists-check in between.
  writeFileSync(paths.transitions, '', { flag: 'a' });
  if (!existsSync(paths.manifest)) {
    writeDurable(paths.manifest, `${JSON.stringify({ version: SCHEMA_VERSION, trustedKeys: [] }, null, 2)}\n`);
    recordTransition(paths, { at: now, action: 'init', detail: `store initialised at ${paths.root}` });
  }
  return paths;
}

export function readManifest(root: string): StoreManifest {
  const paths = storePaths(root);
  if (!existsSync(paths.manifest)) {
    throw new Error(`no case store at ${paths.root}; run: terminal221b case store init --store ${paths.root}`);
  }
  const parsed: unknown = JSON.parse(readFileSync(paths.manifest, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('the store manifest must be a JSON object');
  }
  const value = parsed as Record<string, unknown>;
  if (value.version !== SCHEMA_VERSION) {
    throw new Error(`unsupported store manifest version: ${String(value.version)}`);
  }
  const keys = value.trustedKeys;
  if (!Array.isArray(keys)) throw new Error('the store manifest must list trustedKeys');
  return { version: SCHEMA_VERSION, trustedKeys: keys as TrustedKey[] };
}

export function trustKey(
  root: string,
  key: { keyId: string; publicKey: KeyObject | Buffer; label?: string },
  now: string
): TrustedKey {
  const paths = storePaths(root);
  const manifest = readManifest(root);
  if (manifest.trustedKeys.some((entry) => entry.keyId === key.keyId)) {
    throw new Error(`keyId ${key.keyId} is already trusted; choose another keyId or remove the entry first`);
  }
  const parsedKey = Buffer.isBuffer(key.publicKey)
    ? createPublicKey({ key: key.publicKey, format: 'der', type: 'spki' })
    : key.publicKey;
  const spki = parsedKey.export({ type: 'spki', format: 'der' }) as Buffer;
  // Parse it back: registering a key we cannot construct a verifier from would
  // silently make every record signed by it unverifiable forever.
  createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const entry: TrustedKey = {
    keyId: key.keyId,
    publicKeySpkiDerBase64: spki.toString('base64'),
    ...(key.label === undefined ? {} : { label: key.label }),
    addedAt: now,
  };
  const next: StoreManifest = { version: SCHEMA_VERSION, trustedKeys: [...manifest.trustedKeys, entry] };
  withStoreLock(paths, () => {
    writeDurable(paths.manifest, `${JSON.stringify(next, null, 2)}\n`);
    recordTransition(paths, { at: now, action: 'trust', detail: `trusted key ${key.keyId}` });
  });
  return entry;
}

function trustedKeyObjects(manifest: StoreManifest): Map<string, KeyObject> {
  const out = new Map<string, KeyObject>();
  for (const entry of manifest.trustedKeys) {
    try {
      out.set(
        entry.keyId,
        createPublicKey({
          key: Buffer.from(entry.publicKeySpkiDerBase64, 'base64'),
          format: 'der',
          type: 'spki',
        })
      );
    } catch {
      throw new Error(`trusted key ${entry.keyId} in the store manifest is not a usable public key`);
    }
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Transition log                                                               */
/* -------------------------------------------------------------------------- */

export interface Transition {
  at: string;
  action: string;
  detail?: string;
  entry?: string;
  revision?: number;
  bundleDigest?: string;
}

function recordTransition(paths: StorePaths, transition: Transition): void {
  appendFileSync(paths.transitions, `${JSON.stringify(transition)}\n`);
}

export function readTransitions(root: string): Transition[] {
  const paths = storePaths(root);
  if (!existsSync(paths.transitions)) return [];
  return readFileSync(paths.transitions, 'utf8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as Transition);
}

/* -------------------------------------------------------------------------- */
/* Canonical bytes and signatures (F4)                                          */
/* -------------------------------------------------------------------------- */

/**
 * Deterministic JSON: object keys sorted ascending, no insignificant
 * whitespace, array order preserved, `undefined` omitted. Two runs over equal
 * data produce equal bytes, which is the only property a signature needs.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('cannot canonicalise a non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  throw new Error(`cannot canonicalise a value of type ${typeof value}`);
}

export function sha256(bytes: Buffer | string): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * The attestation is removed before digesting, so attaching, changing, or
 * stripping a signature can never alter what the signature commits to, and a
 * signature can never be transplanted onto a different payload by editing the
 * signature field itself.
 */
export function attestationPayload(record: AttestedRecord): unknown {
  const { attestation: _ignored, ...rest } = record as unknown as Record<string, unknown>;
  return rest;
}

export function payloadDigestOf(record: AttestedRecord): string {
  return sha256(canonicalJson(attestationPayload(record)));
}

/** The exact bytes an ed25519 signature covers. Domain-separated, newline-framed, fixed field order. */
export function signatureInput(kind: AttestedKind, recordId: string, payloadDigest: string): Buffer {
  return Buffer.from(
    `${SIGNATURE_CONTEXT}\n${kind}\n${recordId}\n${payloadDigest}\n`,
    'utf8'
  );
}

export function signRecord(
  kind: AttestedKind,
  record: AttestedRecord,
  privateKey: KeyObject,
  keyId: string,
  signedAt: string
): Attestation {
  const recordId = recordIdOf(record, kind);
  const payloadDigest = payloadDigestOf(record);
  const signature = cryptoSign(null, signatureInput(kind, recordId, payloadDigest), privateKey);
  return {
    keyId,
    algorithm: 'ed25519',
    payloadDigest,
    signature: signature.toString('base64'),
    signedAt,
  };
}

/** Applies signRecord to every human record in a bundle, returning a new bundle. */
export function signBundle(
  bundle: CaseBundle,
  privateKey: KeyObject,
  keyId: string,
  signedAt: string
): CaseBundle {
  const signed: Record<string, unknown> = { ...bundle };
  for (const kind of ATTESTED_KINDS) {
    const list = recordsOfKind(bundle, kind);
    if (list.length === 0) continue;
    signed[BUNDLE_FIELD[kind]] = list.map((entry) => ({
      ...entry,
      attestation: signRecord(kind, entry, privateKey, keyId, signedAt),
    }));
  }
  return signed as unknown as CaseBundle;
}

export function verifyRecord(
  kind: AttestedKind,
  record: AttestedRecord,
  keys: Map<string, KeyObject>
): SignatureReport {
  const recordId = recordIdOf(record, kind);
  const attestation = record.attestation;
  if (!attestation) return { recordKind: kind, recordId, status: 'unsigned' };
  const actual = payloadDigestOf(record);
  if (actual !== attestation.payloadDigest) {
    return { recordKind: kind, recordId, status: 'digest-mismatch', keyId: attestation.keyId };
  }
  const key = keys.get(attestation.keyId);
  if (!key) return { recordKind: kind, recordId, status: 'unknown-key', keyId: attestation.keyId };
  let ok = false;
  try {
    ok = cryptoVerify(
      null,
      signatureInput(kind, recordId, attestation.payloadDigest),
      key,
      Buffer.from(attestation.signature, 'base64')
    );
  } catch {
    ok = false;
  }
  return ok
    ? { recordKind: kind, recordId, status: 'signed', keyId: attestation.keyId }
    : { recordKind: kind, recordId, status: 'bad-signature', keyId: attestation.keyId };
}

export function verifyBundleSignatures(
  bundle: CaseBundle,
  keys: Map<string, KeyObject>
): SignatureReport[] {
  const reports: SignatureReport[] = [];
  for (const kind of ATTESTED_KINDS) {
    for (const record of recordsOfKind(bundle, kind)) {
      reports.push(verifyRecord(kind, record, keys));
    }
  }
  return reports;
}

/**
 * The predicate the eligibility gate consumes. Built from the store manifest, so
 * the trust decision is made once when a key is registered and then merely read
 * at evaluation time. Without a manifest there is no key set, and the gate stays
 * shut.
 */
export function confirmationSignatureChecker(
  manifest: StoreManifest
): (confirmation: ConfirmationRecord) => boolean {
  const keys = trustedKeyObjects(manifest);
  return (confirmation) =>
    verifyRecord('confirmation', confirmation as AttestedRecord, keys).status === 'signed';
}

/**
 * The same predicate for an approval. It exists separately rather than as a
 * parameter because the two are different decisions with different blast
 * radius: a confirmation decides whether a case is eligible, an approval
 * decides whether bytes reach a workspace. Sharing one function would let a
 * later change to one silently widen the other, and the caller still has to
 * check the effect name and the payload digest — a signature alone proves a key
 * signed, not that it signed *this* diff for *this* task.
 */
export function approvalSignatureChecker(
  manifest: StoreManifest
): (approval: ApprovalRecord) => boolean {
  const keys = trustedKeyObjects(manifest);
  return (approval) =>
    verifyRecord('approval', approval as AttestedRecord, keys).status === 'signed';
}

/* -------------------------------------------------------------------------- */
/* Source digests (F5)                                                          */
/* -------------------------------------------------------------------------- */

export type LocalUriScheme = 'file' | 'local';

/**
 * The local path a source's bytes live at, or `undefined` when this store
 * cannot reach them. `file://host/path` names a *host*, so it is treated the
 * same as a remote uri: recorded as unverifiable-here, never fetched. That is
 * reported, not hidden, so a bundle cannot look fully verified when it is not.
 */
export function localPathFor(uri: string, baseDir: string): string | undefined {
  if (uri.startsWith('file://')) {
    let host: string;
    try {
      host = new URL(uri).host;
    } catch {
      return undefined;
    }
    if (host !== '') return undefined;
    return fileURLToPath(uri);
  }
  if (uri.startsWith('local://')) {
    const rest = uri.slice('local://'.length);
    if (rest === '' || rest.includes('..')) return undefined;
    return resolve(baseDir, rest);
  }
  return undefined;
}

async function digestFile(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
  }
  return `sha256:${hash.digest('hex')}`;
}

export interface SourceCheckOptions {
  /** Directory a `local://` uri is resolved against. */
  baseDir: string;
}

/**
 * Recomputes a declared digest where the bytes are reachable, and refuses to
 * guess where they are not. A `local://` path that escapes the base directory
 * is `missing`, not `unverifiable-here`: escaping is a defect in the record, not
 * an honest limitation.
 */
export async function checkSourceDigests(
  bundle: CaseBundle,
  options: SourceCheckOptions
): Promise<SourceVerification[]> {
  const out: SourceVerification[] = [];
  for (const source of bundle.sources) {
    const local = localPathFor(source.uri, options.baseDir);
    if (local === undefined) {
      out.push({
        sourceId: source.sourceId,
        uri: source.uri,
        status: 'unverifiable-here',
        declaredDigest: source.contentDigest,
      });
      continue;
    }
    if (!existsSync(local)) {
      out.push({
        sourceId: source.sourceId,
        uri: source.uri,
        status: 'missing',
        declaredDigest: source.contentDigest,
      });
      continue;
    }
    const actual = await digestFile(local);
    out.push({
      sourceId: source.sourceId,
      uri: source.uri,
      status: actual === source.contentDigest ? 'verified' : 'mismatch',
      declaredDigest: source.contentDigest,
      actualDigest: actual,
    });
  }
  return out;
}

function sourceMismatchProblems(checks: SourceVerification[]): string[] {
  return checks
    .filter((check) => check.status === 'mismatch' || check.status === 'missing')
    .map((check) =>
      check.status === 'mismatch'
        ? `source ${check.sourceId} (${check.uri}) declares ${check.declaredDigest} but the bytes hash to ${check.actualDigest}`
        : `source ${check.sourceId} (${check.uri}) declares ${check.declaredDigest} but its local bytes are not present`
    );
}

/* -------------------------------------------------------------------------- */
/* put / get / verify                                                           */
/* -------------------------------------------------------------------------- */

/**
 * The store is keyed by bundle, not by case. A bundle is one reviewable unit: it
 * carries a scope, a policy snapshot and a set of cases that were all judged
 * against the same snapshot. Splitting it per case would let a later revision
 * change the snapshot while an earlier case's records stayed, which is exactly
 * the split the scope gate exists to prevent.
 */
const SAFE_ENTRY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;

export function entryName(bundle: CaseBundle, explicit?: string): string {
  const name = explicit ?? bundle.cases[0]?.caseId;
  if (!name) throw new Error('a bundle with no cases has nothing to file it under');
  if (!SAFE_ENTRY.test(name) || name.includes('..')) {
    throw new Error(`store entry name must be letters, digits, dot, dash or underscore: ${name}`);
  }
  return name;
}

function listRevisions(paths: StorePaths, entry: string): number[] {
  const dir = join(paths.bundles, entry);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .map((name) => Number(name.replace(/\.json$/, '')))
    .filter((n) => Number.isInteger(n) && n > 0)
    .sort((a, b) => a - b);
}

function bundlePathFor(paths: StorePaths, entry: string, revision: number): string {
  return join(paths.bundles, entry, `${revision}.json`);
}

export interface PutOptions extends SourceCheckOptions {
  now: string;
  /** Store entry name. Default: the first case's id, since a bundle is the unit, not a case. */
  entry?: string;
  /** When false, unsigned human records are accepted but reported. Default: refuse. */
  allowUnsigned?: boolean;
}

/**
 * Accepts a bundle into the store, or refuses it. Refusal happens before any
 * bytes are written: a store that accepts first and complains later is a store
 * whose `verify` result depends on when you asked.
 */
export async function putBundle(root: string, bundle: CaseBundle, options: PutOptions): Promise<PutResult> {
  const paths = storePaths(root);
  const manifest = readManifest(root);
  const problems = validateCaseBundle(bundle);
  if (problems.length > 0) {
    throw new Error(`the bundle is not internally consistent:\n  ${problems.join('\n  ')}`);
  }

  const keys = trustedKeyObjects(manifest);
  const signatures = verifyBundleSignatures(bundle, keys);
  if (!options.allowUnsigned) {
    const unsigned = signatures.filter((entry) => entry.status !== 'signed');
    if (unsigned.length > 0) {
      throw new Error(
        `the store refuses unsigned human records:\n  ${unsigned
          .map((entry) => `${entry.recordKind} ${entry.recordId} is ${entry.status}`)
          .join('\n  ')}\n  sign them first: terminal221b case sign BUNDLE --key KEY --key-id ID`
      );
    }
  }

  const sources = await checkSourceDigests(bundle, options);
  const sourceProblems = sourceMismatchProblems(sources);
  if (sourceProblems.length > 0) {
    throw new Error(`declared digests do not match the local bytes:\n  ${sourceProblems.join('\n  ')}`);
  }

  const entry = entryName(bundle, options.entry);
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  const bundleDigest = sha256(serialized);

  return withStoreLock(paths, () => {
    const revision = (listRevisions(paths, entry).at(-1) ?? 0) + 1;
    writeDurable(bundlePathFor(paths, entry, revision), serialized);
    writeDurable(join(paths.objects, bundleDigest.replace(':', '-')), serialized);
    recordTransition(paths, {
      at: options.now,
      action: 'put',
      entry,
      revision,
      bundleDigest,
      detail: `${signatures.filter((entry) => entry.status === 'signed').length} signed human records`,
    });
    return { entry, revision, bundleDigest, storedAt: options.now, sources };
  });
}

export interface GetOptions extends SourceCheckOptions {
  now: string;
  /** Fail instead of reporting problems. Default true: a store read that cannot be verified is an error. */
  strict?: boolean;
}

export interface GetResult {
  entry: string;
  revision: number;
  bundle: CaseBundle;
  report: VerifyReport;
}

/** Reads a stored bundle back, re-verifying signatures and local digests on the way out. */
export async function getBundle(
  root: string,
  entry: string,
  revision: number | undefined,
  options: GetOptions
): Promise<GetResult> {
  const paths = storePaths(root);
  const revisions = listRevisions(paths, entry);
  if (revisions.length === 0) {
    throw new Error(`the store holds no revisions of ${entry}`);
  }
  const target = revision ?? revisions[revisions.length - 1];
  if (!revisions.includes(target)) {
    throw new Error(`the store holds no revision ${target} of ${entry}; it has ${revisions.join(', ')}`);
  }
  const manifest = readManifest(root);
  const stored = readFileSync(bundlePathFor(paths, entry, target), 'utf8');
  const bundle = parseCaseBundle(JSON.parse(stored));
  const signatures = verifyBundleSignatures(bundle, trustedKeyObjects(manifest));
  const sources = await checkSourceDigests(bundle, options);
  const problems = [
    ...validateCaseBundle(bundle),
    ...sourceMismatchProblems(sources),
    ...signatures
      .filter((entry) => entry.status !== 'signed')
      .map((entry) => `${entry.recordKind} ${entry.recordId} is ${entry.status}`),
  ];
  const report: VerifyReport = { ok: problems.length === 0, problems, entries: [], sources, signatures };
  if (options.strict !== false && !report.ok) {
    throw new Error(`stored revision ${target} of ${entry} does not verify:\n  ${problems.join('\n  ')}`);
  }
  return { entry, revision: target, bundle, report };
}

export function listEntries(root: string): StoreEntry[] {
  const paths = storePaths(root);
  if (!existsSync(paths.bundles)) return [];
  const transitions = readTransitions(root);
  const entries: StoreEntry[] = [];
  for (const name of readdirSync(paths.bundles).sort()) {
    const dir = join(paths.bundles, name);
    if (!existsSync(dir)) continue;
    for (const revision of listRevisions(paths, name)) {
      const recorded = transitions.find(
        (line) => line.entry === name && line.revision === revision && line.bundleDigest
      );
      entries.push({
        entry: name,
        revision,
        bundleDigest: recorded?.bundleDigest,
        storedAt: recorded?.at ?? '',
      });
    }
  }
  return entries;
}

/** Re-checks every stored bundle against the manifest keys and the local bytes. */
export async function verifyStore(
  root: string,
  options: SourceCheckOptions & { now: string }
): Promise<VerifyReport> {
  const paths = storePaths(root);
  const manifest = readManifest(root);
  const keys = trustedKeyObjects(manifest);
  const problems: string[] = [];
  const allSources: SourceVerification[] = [];
  const allSignatures: SignatureReport[] = [];
  const entries = listEntries(root);
  for (const entry of entries) {
    const stored = readFileSync(bundlePathFor(paths, entry.entry, entry.revision), 'utf8');
    const digest = sha256(stored);
    if (entry.bundleDigest === undefined) {
      problems.push(
        `${entry.entry} revision ${entry.revision} has no transition recording its digest, so nothing vouches for these bytes`
      );
    } else if (digest !== entry.bundleDigest) {
      problems.push(`${entry.entry} revision ${entry.revision} no longer hashes to its recorded digest`);
    }
    if (entry.bundleDigest !== undefined) {
      const objectPath = join(paths.objects, entry.bundleDigest.replace(':', '-'));
      if (!existsSync(objectPath) || sha256(readFileSync(objectPath)) !== entry.bundleDigest) {
        problems.push(`${entry.entry} revision ${entry.revision} has no intact stored object`);
      }
    }
    const bundle = parseCaseBundle(JSON.parse(stored));
    problems.push(...validateCaseBundle(bundle).map((line) => `${entry.entry}@${entry.revision}: ${line}`));
    const sources = await checkSourceDigests(bundle, options);
    problems.push(...sourceMismatchProblems(sources).map((line) => `${entry.entry}@${entry.revision}: ${line}`));
    const signatures = verifyBundleSignatures(bundle, keys);
    problems.push(
      ...signatures
        .filter((item) => item.status !== 'signed')
        .map((item) => `${entry.entry}@${entry.revision}: ${item.recordKind} ${item.recordId} is ${item.status}`)
    );
    allSources.push(...sources);
    allSignatures.push(...signatures);
  }
  return { ok: problems.length === 0, problems, entries, sources: allSources, signatures: allSignatures };
}

/* -------------------------------------------------------------------------- */
/* Key files (operator-supplied; never written by this module)                 */
/* -------------------------------------------------------------------------- */

export function readPrivateKeyPem(path: string): KeyObject {
  const text = readFileSync(path, 'utf8');
  if (!text.includes('PRIVATE KEY')) {
    throw new Error(`${path} does not contain a PRIVATE KEY block; a public key cannot sign`);
  }
  try {
    return createPrivateKey(text);
  } catch (error) {
    throw new Error(`${path} is not a readable private key: ${(error as Error).message}`);
  }
}

export function readPublicKeyDer(path: string): KeyObject {
  return createPublicKey({ key: readFileSync(path), format: 'der', type: 'spki' });
}

/* -------------------------------------------------------------------------- */
/* Retention enforcement (F10)                                                  */
/* -------------------------------------------------------------------------- */

/**
 * A `retention` class records an intention, and until now nothing acted on it
 * (F10). This section makes the intention checkable and enforceable, with two
 * deliberate restraints.
 *
 * **No window is applied unless the operator wrote one.** How long outcome data
 * may be kept was open decision 3 in the blueprint. It has since been answered
 * (7 / 180 / 180 days, and `operator_archive` never), and `DEFAULT_RETENTION_POLICY`
 * below is that decision — but it is a *starting* policy written into an operator
 * file by `case store retention --record-default-policy`, not a window applied
 * behind the operator's back. `retentionReport` itself takes its windows as an
 * argument and applies nothing of its own: a class with no window is reported
 * `unconfigured` rather than treated as safe, and `operator_archive` has no
 * window at all because the operator already chose to keep it. The rule that
 * matters is that the report never guesses, so purging stays a reviewed act.
 *
 * **Purge removes whole revisions, never single sources.** A bundle's signature
 * covers the whole bundle, so dropping one source out of the middle would
 * rewrite signed bytes and silently invalidate every attestation in the file.
 * Deleting a revision removes the evidence without falsifying any signature, so
 * that is what the gesture does.
 *
 * Age is measured from `observedAt`, which the operator records. The freshness
 * review is explicit that this makes the number a statement about
 * record-keeping, not about the source, and the report says so on its face.
 */

export type RetentionStatus =
  | 'never-expires'
  | 'unconfigured'
  | 'within-window'
  | 'past-window'
  | 'past-window-newest-revision';

export interface RetentionRow {
  entry: string;
  revision: number;
  sourceId: string;
  uri: string;
  retention: string;
  observedAt: string;
  ageDays: number | null;
  status: RetentionStatus;
}

export interface RetentionReport {
  /** The instant the ages were computed against. */
  now: string;
  rows: RetentionRow[];
  counts: Record<RetentionStatus, number>;
  /** Revisions holding at least one past-window source, as `entry@revision`. */
  purgeable: string[];
  /**
   * Digest of the purgeable set. A purge must present this, so it cannot happen
   * without a report having been read first, and a store that changed in between
   * invalidates it.
   */
  token: string;
}

export interface RetentionWindows {
  transient?: number;
  case_metadata?: number;
  local_diff?: number;
}

function windowFor(windows: RetentionWindows, retention: string): number | undefined {
  if (retention === 'operator_archive') return undefined;
  const days = (windows as Record<string, number | undefined>)[retention];
  return typeof days === 'number' ? days : undefined;
}

function ageInDays(observedAt: string, now: string): number | null {
  const observed = Date.parse(observedAt);
  const reference = Date.parse(now);
  if (!Number.isFinite(observed) || !Number.isFinite(reference)) return null;
  return Math.floor((reference - observed) / 86_400_000);
}

/**
 * Computes, and mutates nothing. Every source of every stored revision gets a
 * row, so the answer to "what would a purge take" is visible before anyone asks
 * for a purge.
 */
export function retentionReport(root: string, windows: RetentionWindows, now: string): RetentionReport {
  const paths = storePaths(root);
  if (!existsSync(paths.bundles)) {
    return { now, rows: [], counts: emptyCounts(), purgeable: [], token: sha256('retention:empty') };
  }
  const newest = new Map<string, number>();
  for (const entry of listEntries(paths.root)) {
    const current = newest.get(entry.entry);
    if (current === undefined || entry.revision > current) newest.set(entry.entry, entry.revision);
  }

  const rows: RetentionRow[] = [];
  for (const stored of listEntries(paths.root)) {
    const bundle = parseCaseBundle(JSON.parse(readFileSync(bundlePathFor(paths, stored.entry, stored.revision), 'utf8')));
    const isNewest = newest.get(stored.entry) === stored.revision;
    for (const source of bundle.sources) {
      const days = windowFor(windows, source.retention);
      const ageDays = ageInDays(source.observedAt, now);
      let status: RetentionStatus;
      if (source.retention === 'operator_archive') {
        status = 'never-expires';
      } else if (days === undefined) {
        status = 'unconfigured';
      } else if (ageDays === null) {
        status = 'unconfigured';
      } else if (ageDays > days) {
        // The newest revision is the live one. It is reported past its window so
        // the operator sees the debt, but it is never a purge candidate: the
        // store always keeps something current.
        status = isNewest ? 'past-window-newest-revision' : 'past-window';
      } else {
        status = 'within-window';
      }
      rows.push({
        entry: stored.entry,
        revision: stored.revision,
        sourceId: source.sourceId,
        uri: source.uri,
        retention: source.retention,
        observedAt: source.observedAt,
        ageDays,
        status,
      });
    }
  }

  const purgeable = [
    ...new Set(rows.filter((row) => row.status === 'past-window').map((row) => `${row.entry}@${row.revision}`)),
  ].sort();
  return {
    now,
    rows,
    counts: countStatuses(rows),
    purgeable,
    token: sha256(canonicalJson({ now, purgeable })),
  };
}

function emptyCounts(): Record<RetentionStatus, number> {
  return {
    'never-expires': 0,
    unconfigured: 0,
    'within-window': 0,
    'past-window': 0,
    'past-window-newest-revision': 0,
  };
}

function countStatuses(rows: RetentionRow[]): Record<RetentionStatus, number> {
  const counts = emptyCounts();
  for (const row of rows) counts[row.status] += 1;
  return counts;
}

export interface PurgeResult {
  removed: { entry: string; revision: number; sources: string[] }[];
  token: string;
}

/**
 * Deletes the revisions the report named, and nothing else. The token is
 * recomputed here from the store as it is now, so a stale token refuses rather
 * than deleting something the operator never saw.
 */
export function purgeExpired(
  root: string,
  windows: RetentionWindows,
  now: string,
  token: string
): PurgeResult {
  const paths = storePaths(root);
  const report = retentionReport(root, windows, now);
  if (report.purgeable.length === 0) {
    throw new Error(
      'nothing is past its retention window, so there is nothing to purge; run the report first and look at it'
    );
  }
  if (token !== report.token) {
    throw new Error(
      `the retention token does not match this store as it is now: the report says ${report.token}, you presented ${token}. Re-run the report and use the token it prints.`
    );
  }

  const removed: PurgeResult['removed'] = [];
  return withStoreLock(paths, () => {
    for (const item of report.purgeable) {
      const at = item.lastIndexOf('@');
      const entry = item.slice(0, at);
      const revision = Number(item.slice(at + 1));
      const sources = report.rows
        .filter((row) => row.entry === entry && row.revision === revision && row.status === 'past-window')
        .map((row) => row.sourceId);
      rmSync(bundlePathFor(paths, entry, revision), { force: true });
      recordTransition(paths, {
        at: now,
        action: 'purge',
        entry,
        revision,
        detail: `removed past its retention window: ${sources.join(', ')}`,
      });
      removed.push({ entry, revision, sources });
    }

    // The object store is content-addressed, so two revisions of the same bundle
    // share one object file. Deleting the object of a purged revision would
    // therefore delete the bytes a *surviving* revision still points at, and the
    // store would fail its own integrity check on a store nothing tampered
    // with. An object is only orphaned once no surviving revision names it.
    const stillReferenced = new Set(
      listEntries(paths.root)
        .map((stored) => stored.bundleDigest)
        .filter((digest): digest is string => digest !== undefined)
    );
    const purgedDigests = new Set(
      removed
        .map(({ entry, revision }) =>
          readTransitions(root).find(
            (line) => line.entry === entry && line.revision === revision && line.bundleDigest
          )?.bundleDigest
        )
        .filter((digest): digest is string => digest !== undefined)
    );
    for (const digest of purgedDigests) {
      if (!stillReferenced.has(digest)) {
        rmSync(join(paths.objects, digest.replace(':', '-')), { force: true });
      }
    }
    return { removed, token: report.token };
  });
}

/**
 * Re-exported unchanged from the contracts, so `cli.ts` keeps importing the
 * class list from one place while there is only one definition of it.
 */
export { RETENTION_CLASSES };

/**
 * Open decision 3 answered, on 2026-10-02: **7 / 180 / 180 days, and the archive
 * never expires.** These numbers are an approved policy, not a discovered truth,
 * and they stay in a file the operator can edit rather than compiled in, so that
 * changing the policy is a reviewable edit and not a code change.
 *
 * The reasoning behind each:
 *
 * - `transient` 7d. Re-derivable by re-running the tool that produced it, which
 *   is the entire reason the class exists.
 * - `case_metadata` 180d. 90 days is when the *eligibility gate* stops caring,
 *   but a lead that goes cold for a quarter and revives is exactly the case
 *   where the notes are worth something. Reusing 90 for both policy freshness
 *   and evidence retention would be a category error: they are different
 *   concepts. 365 is too long to sit on third-party program material.
 * - `local_diff` 180d. The operator's own work product, the least likely to be
 *   re-creatable and the least likely to be a rights problem, so being generous
 *   costs nothing and losing it costs real work.
 * - `operator_archive` has no window, by decision rather than by omission. The
 *   operator explicitly chose to keep their own receipt, and it is their
 *   artifact, not a third party's.
 *
 * Recording this file is what unblocks Phase 1. It does not by itself graduate
 * Phase 1: README roadmap item 7 also names the isolated worktree, which is
 * Phase 3.
 */
export const DEFAULT_RETENTION_POLICY: RetentionWindows = {
  transient: 7,
  case_metadata: 180,
  local_diff: 180,
};

function retentionPolicyPath(paths: StorePaths): string {
  return join(paths.root, 'retention.json');
}

export interface RetentionPolicyFile {
  version: 1;
  /** Non-fatal context for whoever reads the file next. */
  note?: string;
  /** Whole days per class. `operator_archive` is absent by design. */
  windows: RetentionWindows;
}

/** The store's policy file, or undefined when the operator has written none. */
export function loadRetentionPolicy(root: string): RetentionPolicyFile | undefined {
  const at = retentionPolicyPath(storePaths(root));
  if (!existsSync(at)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(at, 'utf8'));
  } catch (error) {
    throw new Error(`${at} is not readable JSON: ${(error as Error).message}`);
  }
  const file = parsed as Partial<RetentionPolicyFile>;
  if (file.version !== 1) {
    throw new Error(`${at} has version ${String(file.version)}; this store understands version 1`);
  }
  const windows = file.windows;
  if (typeof windows !== 'object' || windows === null) {
    throw new Error(`${at} has no windows object`);
  }
  for (const [key, value] of Object.entries(windows)) {
    if (!RETENTION_CLASSES.includes(key as (typeof RETENTION_CLASSES)[number])) {
      throw new Error(`${at} names an unknown retention class: ${key}`);
    }
    if (!Number.isInteger(value) || (value as number) < 0) {
      throw new Error(`${at} gives ${key} a window that is not a whole number of days: ${String(value)}`);
    }
  }
  return { version: 1, note: file.note, windows: windows as RetentionWindows };
}

export function saveRetentionPolicy(
  root: string,
  windows: RetentionWindows,
  now: string
): { path: string; overwritten: boolean } {
  const paths = storePaths(root);
  const at = retentionPolicyPath(paths);
  const existing = existsSync(at);
  mkdirSync(paths.root, { recursive: true });
  const ordered: Record<string, number> = {};
  for (const key of RETENTION_CLASSES) {
    if (key === 'operator_archive') continue;
    const value = (windows as Record<string, number | undefined>)[key];
    if (typeof value === 'number') ordered[key] = value;
  }
  const file: RetentionPolicyFile = {
    version: 1,
    note:
      'How long each retention class may be kept. This file is the answer to blueprint open decision 3. ' +
      'A class absent from here is reported unconfigured and is never purged. operator_archive is never purged.',
    windows: ordered as RetentionWindows,
  };
  writeDurable(at, `${JSON.stringify(file, null, 2)}\n`);
  recordTransition(paths, {
    at: now,
    action: existing ? 'retention-policy-replaced' : 'retention-policy-recorded',
    detail: `windows: ${Object.entries(ordered).map(([key, value]) => `${key}=${value}d`).join(', ') || 'none'}`,
  });
  return { path: at, overwritten: existing };
}
