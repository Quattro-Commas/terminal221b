#!/usr/bin/env node

import { createInterface } from 'node:readline/promises';
import { spawnSync } from 'node:child_process';
import { stdin, stdout } from 'node:process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { runLocalAnalyzers } from './analyzers.js';
import { askAnthropic } from './anthropic.js';
import { applyApprovedPatch } from './patch.js';
import { scanLocalWorkspace } from './security.js';
import { loadBountyScope } from './scope.js';
import { loadCaseBundle, parseTaskContract, validateCaseBundle } from './case.js';
import { fixtureBundleJson } from './case-fixtures.js';
import { dossierReport, renderDossier } from './dossier.js';
import {
  confirmationSignatureChecker,
  readNoticeLines,
  getBundle,
  initStore,
  putBundle,
  readManifest,
  loadRetentionPolicy,
  saveRetentionPolicy,
  DEFAULT_RETENTION_POLICY,
  purgeExpired,
  retentionReport,
  RETENTION_CLASSES,
  type RetentionWindows,
  readPrivateKeyPem,
  readPublicKeyDer,
  resolveStoreRoot,
  signBundle,
  trustKey,
  verifyStore,
} from './store.js';
import { discoverTools } from './tools.js';
import { collectWorkspaceContext } from './workspace.js';
import {
  appendEvents,
  applyTaskDiff,
  candidateDiffPath,
  runTask,
  taskEventsPath,
} from './executor.js';
import { describeFailure, exitCodeFor, type SystemProfile } from './provider.js';
import {
  AGENT_ROLES,
  profileForRole,
  renderSystemPrompt,
  type AgentRole,
} from './system-prompt.js';

const defaultModel = 'claude-sonnet-4-5-20250929';

function printHelp(): void {
  console.log(`Terminal221b local coding assistant

Usage:
  terminal221b ask [--workspace PATH] [--apply] [--role ROLE] PROMPT
  terminal221b tui [WORKSPACE]
  terminal221b crypto ask [--workspace PATH] [--apply] PROMPT
  terminal221b security scan [--workspace PATH] [--with-gitleaks] [--with-bandit]
    [--with-semgrep] [--with-trivy] [--with-slither] [--with-cargo-audit]
  terminal221b scope validate PATH
  terminal221b case dossier PATH [--now ISO8601] [--policy-max-age-days N] [--store DIR] [--json]
  terminal221b case template
  terminal221b case store init [--store DIR] [--public-key FILE --key-id ID]
  terminal221b case store put PATH [--store DIR] [--base-dir DIR] [--entry NAME]
  terminal221b case store get ENTRY [--revision N] [--store DIR] [--base-dir DIR]
  terminal221b case store verify [--store DIR] [--base-dir DIR]
  terminal221b case task run CONTRACT.json [--workspace PATH] [--base-dir DIR] [--json]
    [--allow-unsandboxed]
  terminal221b case task apply CONTRACT.json APPROVAL.json [--workspace PATH] [--store DIR]
  terminal221b case sign PATH --key PRIVATE.pem --key-id ID [--signed-at ISO8601]
  terminal221b tools
  terminal221b setup omarchy --dry-run

Options:
  --workspace PATH  Limit repository context to this directory (default: cwd)
  --apply            Ask for a unified diff and require explicit approval to apply
  --role ROLE        Run as ROLE (scout, analyst, engineer, artist, reviewer).
                     Only analyst selects its own system profile; the others run
                     the coding profile. Not accepted by crypto ask.
  --store DIR        Case store root (default: $XDG_DATA_HOME/terminal221b)
  --base-dir DIR     Directory that local:// source uris resolve against
  --help             Show this help

The CLI reads local text files and sends them with your prompt to Anthropic.
The crypto mode focuses on software, protocol, NFT, and market-design discussion.
It never runs model-generated shell commands. Applying a patch requires typing APPLY.
Security scans inspect local files only; optional scanners run only when explicitly selected.
Semgrep uses bundled local rules; Trivy and cargo-audit do not fetch databases during a scan.
Slither checks discovered Solidity files only and does not run a project build.
Scope validation never sends target requests.
The case dossier is local and offline: it ranks recorded cases by evidence, never by an
estimated payout. A case reaches the actionable queue only when a human confirmation is
pinned to one exact asset and one exact policy snapshot AND carries a signature that
verifies against a key a case store trusts; without a --store the gate stays shut. The
freshness limit defaults to
90 days and is yours to set with --policy-max-age-days; it is a working default, not a
program rule, and it is measured from a timestamp you recorded, not from anything this
tool verifies. A fact claim must carry deterministic or operator-confirmed verification.
Nothing here contacts a target, submits anything, or holds signing keys. The case store keeps
bundles, recomputes local source digests, and checks detached ed25519 signatures; it holds no
private key, and case sign reads one from a file you name and never copies it anywhere.
Omarchy setup prints a package plan only and never installs software.
`);
}

function parseArgs(args: string[]): {
  workspace: string;
  prompt: string;
  apply: boolean;
  role: AgentRole | undefined;
} {
  let workspace = process.cwd();
  let apply = false;
  let role: AgentRole | undefined;
  const prompt: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === '--workspace') {
      const value = args[index + 1];
      if (!value) throw new Error('--workspace requires a directory path');
      workspace = resolve(value);
      index += 1;
    } else if (arg === '--apply') {
      apply = true;
    } else if (arg === '--role') {
      const value = args[index + 1];
      if (!value) throw new Error('--role requires a role name');
      if (!(AGENT_ROLES as readonly string[]).includes(value)) {
        throw new Error(`--role must be one of: ${AGENT_ROLES.join(', ')}`);
      }
      role = value as AgentRole;
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      prompt.push(arg);
    }
  }

  const value = prompt.join(' ').trim();
  if (!value) throw new Error('Provide a prompt after the ask command');
  return { workspace, prompt: value, apply, role };
}

async function confirmPatch(paths: string[], patch: string): Promise<boolean> {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error('Patch approval requires an interactive terminal');
  }

  console.log(`\nPatch targets (${paths.length}):`);
  for (const path of paths) console.log(`  ${path}`);
  console.log('\nProposed diff:\n');
  console.log(patch);
  const terminal = createInterface({ input: stdin, output: stdout });
  try {
    return (await terminal.question('Type APPLY to write these changes: ')) === 'APPLY';
  } finally {
    terminal.close();
  }
}

function workspaceOption(args: string[]): string {
  let workspace = process.cwd();
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== '--workspace') continue;
    const value = args[index + 1];
    if (!value) throw new Error('--workspace requires a directory path');
    workspace = resolve(value);
    index += 1;
  }
  return workspace;
}

async function showTools(): Promise<void> {
  const tools = await discoverTools();
  for (const category of ['security', 'solana/crypto'] as const) {
    console.log(`\n${category}`);
    for (const tool of tools.filter((entry) => entry.category === category)) {
      const status = tool.executable ?? 'not found';
      console.log(`  ${tool.name}: ${status}`);
      console.log(`    ${tool.purpose} (${tool.documentation})`);
    }
  }
  console.log('\nDiscovery checks PATH only; it does not execute or install tools.');
}

async function runSecurityScan(args: string[]): Promise<void> {
  const workspace = workspaceOption(args);
  const selected = {
    gitleaks: args.includes('--with-gitleaks'),
    bandit: args.includes('--with-bandit'),
    semgrep: args.includes('--with-semgrep'),
    trivy: args.includes('--with-trivy'),
    slither: args.includes('--with-slither'),
    cargoAudit: args.includes('--with-cargo-audit'),
  };
  const result = await scanLocalWorkspace(workspace);
  const tools = await discoverTools();
  result.findings.push(
    ...runLocalAnalyzers(result.root, result.sourceFiles, tools, selected)
  );
  console.log(
    `Local scan: ${result.root} (${result.filesScanned} files, ${result.bytesScanned} bytes)`
  );
  console.log('Local analyzers and heuristic triage only. No network targets are contacted.');
  console.log(
    `Selected analyzers: ${[
      selected.gitleaks && 'Gitleaks',
      selected.bandit && 'Bandit',
      selected.semgrep && 'Semgrep',
      selected.trivy && 'Trivy',
      selected.slither && 'Slither',
      selected.cargoAudit && 'cargo-audit',
    ].filter(Boolean).join(', ') || 'built-in heuristics only'}`
  );
  for (const finding of result.findings) {
    console.log(
      `${finding.file}:${finding.line} [${finding.severity}] ${finding.rule}: ${finding.message}`
    );
  }
  if (result.truncated) {
    console.warn('Scan limits reached; results are incomplete.');
  }
  if (result.findings.length === 0) console.log('No configured pattern matches.');
  if (result.findings.some((finding) => finding.severity === 'high')) process.exitCode = 1;
}

async function validateScope(args: string[]): Promise<void> {
  const path = args[0];
  if (!path || args.length !== 1) {
    throw new Error('Usage: terminal221b scope validate PATH');
  }
  const manifest = await loadBountyScope(path);
  console.log(`Validated scope metadata for ${manifest.program}.`);
  console.log(`Policy: ${manifest.policyUrl}`);
  console.log(`In-scope entries: ${manifest.inScope.length}`);
  console.log(`Out-of-scope entries: ${manifest.outOfScope?.length ?? 0}`);
  console.log('Validation only; no target requests are made.');
}

function evaluationOption(args: string[], flag: string, label: string): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value) throw new Error(`${flag} requires ${label}`);
  return value;
}

/** Every `--flag value` pair in one pass, for a command that takes several at once. */
function optionsOnly(args: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [index, arg] of args.entries()) {
    if (!arg.startsWith('--')) continue;
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) continue;
    out[arg] = value;
  }
  return out;
}

/**
 * Only the arguments that are *not* a flag's value. Rejecting anything that does
 * not start with `--` is wrong here: `--workspace /tmp/repo` is well formed, and a
 * guard that reads it as a stray positional refuses every real invocation.
 */
function positionalsOf(args: string[]): string[] {
  const out: string[] = [];
  for (const [index, arg] of args.entries()) {
    if (arg.startsWith('--')) continue;
    const previous = args[index - 1];
    if (previous !== undefined && previous.startsWith('--')) continue;
    out.push(arg);
  }
  return out;
}

async function showCaseDossier(args: string[]): Promise<void> {
  const path = args.find((arg) => !arg.startsWith('--'));
  if (!path) {
    throw new Error('Usage: terminal221b case dossier PATH [--now ISO8601] [--policy-max-age-days N] [--store DIR] [--json]');
  }
  const now = evaluationOption(args, '--now', 'an ISO-8601 UTC timestamp') ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(now))) {
    throw new Error('--now must be an ISO-8601 UTC timestamp such as 2026-09-30T12:00:00Z');
  }
  const rawMaxAge = evaluationOption(args, '--policy-max-age-days', 'a number of days');
  const policyMaxAgeDays = rawMaxAge === undefined ? 90 : Number(rawMaxAge);
  if (!Number.isInteger(policyMaxAgeDays) || policyMaxAgeDays < 1) {
    throw new Error('--policy-max-age-days must be a positive whole number of days');
  }
  const bundle = await loadCaseBundle(path);
  const problems = validateCaseBundle(bundle);
  // A bundle read off disk carries no trust decision of its own, so the gate
  // stays shut unless the caller points at a store whose manifest names keys.
  // A missing --store is not an error: the dossier still renders, and every
  // confirmed case is reported as awaiting a signature rather than as queued.
  const rawStore = evaluationOption(args, '--store', 'a store directory');
  const confirmationSigned = rawStore
    ? confirmationSignatureChecker(readManifest(resolveStoreRoot(rawStore)))
    : undefined;
  // `--json` is purely additive: the markdown below is byte-for-byte what it
  // was before this flag existed, and every consumer that wanted prose keeps
  // getting prose. The structured form exists for the terminal screen, which
  // displays the gate's words rather than re-deriving them.
  if (args.includes('--json')) {
    const storeRoot = rawStore ? resolveStoreRoot(rawStore) : undefined;
    process.stdout.write(
      `${JSON.stringify(
        dossierReport(
          bundle,
          { now, policyMaxAgeDays, confirmationSigned },
          {
            signatureTrust: rawStore ? 'trusted-store' : 'no-store',
            ...(storeRoot === undefined ? {} : { storeRoot }),
          }
        ),
        null,
        2
      )}\n`
    );
    if (problems.length > 0) process.exitCode = 1;
    return;
  }
  process.stdout.write(renderDossier(bundle, { now, policyMaxAgeDays, confirmationSigned }));
  if (problems.length > 0) process.exitCode = 1;
}

function printCaseTemplate(): void {
  process.stdout.write(`${JSON.stringify(fixtureBundleJson, null, 2)}\n`);
}

const STORE_USAGE =
  'Usage: terminal221b case store init|put|get|verify|retention [--store DIR] [--base-dir DIR] [--record-default-policy] ...';

function storeRootFrom(args: string[]): string {
  return resolveStoreRoot(evaluationOption(args, '--store', 'a store directory'));
}

function baseDirFrom(args: string[]): string {
  return resolve(evaluationOption(args, '--base-dir', 'a directory to resolve local:// against') ?? process.cwd());
}

function signedAtFrom(args: string[]): string {
  const at = evaluationOption(args, '--signed-at', 'an ISO-8601 UTC timestamp') ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(at))) {
    throw new Error('--signed-at must be an ISO-8601 UTC timestamp such as 2026-09-30T12:00:00Z');
  }
  return at;
}

async function runCaseStore(args: string[]): Promise<void> {
  const [verb, ...rest] = args;
  if (verb === 'init') {
    const root = storeRootFrom(args);
    const now = signedAtFrom(args);
    await initStore(root, now);
    const keyFile = evaluationOption(args, '--public-key', 'a public key file');
    if (keyFile) trustKey(root, { keyId: keyIdFrom(args), publicKey: readPublicKeyDer(keyFile) }, now);
    process.stdout.write(`Store ready at ${root}\n`);
    if (keyFile) process.stdout.write(`Trusted key ${keyIdFrom(args)}\n`);
    process.stdout.write('Store it outside any repository so nothing it holds is ever committed.\n');
    return;
  }
  if (verb === 'verify') {
    const root = storeRootFrom(args);
    const report = await verifyStore(root, { baseDir: baseDirFrom(args), now: signedAtFrom(args) });
    for (const problem of report.problems) process.stdout.write(`problem: ${problem}\n`);
    process.stdout.write(
      `${report.entries.length} stored revision(s), ${report.signatures.length} signature(s), ` +
        `${report.sources.filter((entry) => entry.status === 'verified').length} source(s) re-verified locally, ` +
        `${report.sources.filter((entry) => entry.status === 'unverifiable-here').length} unverifiable here\n`
    );
    process.stdout.write(report.ok ? 'store verifies\n' : 'store does not verify\n');
    if (!report.ok) process.exitCode = 1;
    return;
  }
  if (verb === 'put') {
    const path = rest.find((arg) => !arg.startsWith('--'));
    if (!path) throw new Error(`Usage: terminal221b case store put PATH ${STORE_USAGE}`);
    const root = storeRootFrom(args);
    const result = await putBundle(root, await loadCaseBundle(path), {
      now: signedAtFrom(args),
      baseDir: baseDirFrom(args),
      entry: evaluationOption(args, '--entry', 'a store entry name'),
    });
    process.stdout.write(
      `stored ${result.entry} revision ${result.revision} as ${result.bundleDigest}\n` +
        `${result.sources.filter((entry) => entry.status === 'verified').length} source(s) verified locally, ` +
        `${result.sources.filter((entry) => entry.status === 'unverifiable-here').length} unverifiable here\n`
    );
    return;
  }
  if (verb === 'get') {
    const entry = rest.find((arg) => !arg.startsWith('--'));
    if (!entry) throw new Error(`Usage: terminal221b case store get ENTRY [--revision N] ${STORE_USAGE}`);
    const rawRevision = evaluationOption(args, '--revision', 'a revision number');
    const revision = rawRevision === undefined ? undefined : Number(rawRevision);
    if (revision !== undefined && (!Number.isInteger(revision) || revision < 1)) {
      throw new Error('--revision must be a positive whole number');
    }
    const got = await getBundle(storeRootFrom(args), entry, revision, {
      baseDir: baseDirFrom(args),
      now: signedAtFrom(args),
      strict: evaluationOption(args, '--no-verify', 'nothing') === undefined,
    });
    for (const line of readNoticeLines(got)) process.stderr.write(`${line}\n`);
    process.stdout.write(`${JSON.stringify(got.bundle, null, 2)}\n`);
    return;
  }
  if (verb === 'retention') {
    const root = storeRootFrom(args);
    const now = signedAtFrom(args);

    // Recording the policy is the answer to open decision 3, so it is its own
    // gesture rather than a side effect of asking for a report.
    if (args.includes('--record-default-policy')) {
      const saved = saveRetentionPolicy(root, DEFAULT_RETENTION_POLICY, now);
      process.stdout.write(
        `${saved.overwritten ? 'replaced' : 'recorded'} the retention policy at ${saved.path}\n` +
          `${Object.entries(DEFAULT_RETENTION_POLICY).map(([key, days]) => `${key}=${days}d`).join(', ')}\n` +
          'operator_archive has no window and is never purged. A class absent from the file is unconfigured and is never purged.\n' +
          'This is a starting position, not a measured one. Edit the file to change it; a --*-days flag overrides it for one run.\n'
      );
      return;
    }

    const { windows, source } = retentionWindowsFrom(args, root);
    const token = evaluationOption(args, '--purge', 'the token the report printed');
    if (token === undefined) {
      const report = retentionReport(root, windows, now);
      for (const row of report.rows) {
        process.stdout.write(
          `${row.status}  ${row.entry}@${row.revision}  ${row.sourceId}  ${row.retention}  ` +
            `${row.ageDays === null ? 'age unknown' : `${row.ageDays}d`}  ${row.uri}\n`
        );
      }
      process.stdout.write(
        `${report.counts['past-window']} past its window, ` +
          `${report.counts['past-window-newest-revision']} past its window on the newest revision (kept), ` +
          `${report.counts.unconfigured} with no window configured, ` +
          `${report.counts['within-window']} within, ` +
          `${report.counts['never-expires']} never expiring\n`
      );
      process.stdout.write(`windows from: ${source}\n`);
      if (report.counts.unconfigured > 0) {
        process.stdout.write(
          'A class with no window is not treated as safe to delete. Record a policy with --record-default-policy, or set one per class.\n'
        );
      }
      if (report.purgeable.length > 0) {
        process.stdout.write(
          `to purge ${report.purgeable.join(', ')}:\n` +
            `  terminal221b case store retention --purge ${report.token}${storeFlags(args)}\n` +
            'A purge removes a whole revision and its object, never a single record, so it cannot falsify a surviving signature.\n'
        );
      } else {
        process.stdout.write('nothing is purgeable\n');
      }
      process.stdout.write('Age is measured from observedAt, which you record. It describes your record-keeping, not the source.\n');
      return;
    }
    const result = purgeExpired(root, windows, now, token);
    for (const item of result.removed) {
      process.stdout.write(`purged ${item.entry} revision ${item.revision}: ${item.sources.join(', ')}\n`);
    }
    process.stdout.write(`${result.removed.length} revision(s) removed, windows from ${source}\n`);
    return;
  }
  throw new Error(STORE_USAGE);
}

function storeFlags(args: string[]): string {
  const store = evaluationOption(args, '--store', 'a store directory');
  return store ? ` --store ${store}` : '';
}

/**
 * Precedence is flags, then the store's policy file, then nothing. A flag
 * always wins so a one-off run can be stricter than the recorded policy without
 * editing the file, and a store with no policy file still reports every class
 * as unconfigured rather than falling back to a built-in schedule.
 */
function retentionWindowsFrom(args: string[], root: string): { windows: RetentionWindows; source: string } {
  const windows: Record<string, number> = {};
  let anyFlag = false;
  for (const retention of RETENTION_CLASSES) {
    if (retention === 'operator_archive') continue;
    const raw = evaluationOption(args, `--${retention.replace('_', '-')}-days`, `${retention} retention days`);
    if (raw === undefined) continue;
    const days = Number(raw);
    if (!Number.isInteger(days) || days < 0) {
      throw new Error(`--${retention.replace('_', '-')}-days must be a whole number of days, zero or more`);
    }
    windows[retention] = days;
    anyFlag = true;
  }
  if (anyFlag) return { windows, source: 'command line' };
  const policy = loadRetentionPolicy(root);
  if (policy) return { windows: policy.windows, source: `policy file ${policyFileLabel(root)}` };
  return { windows: {}, source: 'no policy: every class is unconfigured and nothing is purgeable' };
}

function policyFileLabel(root: string): string {
  return join(root, 'retention.json');
}

function keyIdFrom(args: string[]): string {
  const keyId = evaluationOption(args, '--key-id', 'a key identifier');
  if (!keyId) throw new Error('a signature must name the key it was made with; pass --key-id');
  return keyId;
}

/**
 * Signs a bundle with an operator-held key. The key is read from disk and
 * never copied, logged, or written into the bundle or the store: only the
 * signature leaves this function.
 */
async function signCaseBundle(args: string[]): Promise<void> {
  const path = args.find((arg) => !arg.startsWith('--'));
  if (!path) {
    throw new Error('Usage: terminal221b case sign PATH --key PRIVATE.pem --key-id ID [--signed-at ISO8601]');
  }
  const keyId = keyIdFrom(args);
  const keyFile = evaluationOption(args, '--key', 'a private key file');
  if (!keyFile) throw new Error('case sign needs --key pointing at an ed25519 private key file');
  const signed = signBundle(
    await loadCaseBundle(path),
    readPrivateKeyPem(keyFile),
    keyId,
    signedAtFrom(args)
  );
  process.stdout.write(`${JSON.stringify(signed, null, 2)}\n`);
}

async function printOmarchyPlan(args: string[]): Promise<void> {
  if (args.length !== 1 || args[0] !== '--dry-run') {
    throw new Error('Usage: terminal221b setup omarchy --dry-run');
  }
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const scriptPath = fileURLToPath(
    new URL('../resources/omarchy-toolchain-plan.sh', import.meta.url)
  );
  const result = spawnSync('bash', [scriptPath, '--dry-run'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '' },
    maxBuffer: 100_000,
    timeout: 10_000,
  });
  if (result.error) throw new Error(`Could not run Omarchy preflight: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`Omarchy preflight failed (exit ${result.status}); stderr was suppressed.`);
  }
  process.stdout.write(result.stdout);
}

function launchTui(args: string[]): void {
  const result = spawnSync('terminal221b-tui', args, {
    stdio: 'inherit',
    env: process.env,
  });
  if (result.error) {
    throw new Error(
      `Could not start the Rust TUI (${result.error.message}); install terminal221b-tui and ensure it is on PATH`
    );
  }
  if (result.status !== 0) {
    throw new Error(`Rust TUI exited with status ${result.status ?? 'unknown'}`);
  }
}

const TASK_USAGE =
  'Usage: terminal221b case task run CONTRACT.json [--workspace PATH] [--base-dir DIR] [--json]\n' +
  '         [--allow-unsandboxed]\n' +
  '       | case task apply CONTRACT.json APPROVAL.json [--workspace PATH] [--store DIR]';

/** A ```diff fence if the model used one, otherwise the whole answer. One place, so the two callers agree. */
function patchFromAnswer(answer: string): string {
  const match = answer.match(/```diff\s*\n([\s\S]*?)```/);
  return (match?.[1] ?? answer).trim();
}

/**
 * Run one task contract and leave a reviewable candidate behind.
 *
 * The candidate is written to disk under `.terminal221b/tasks/<taskId>.diff` and
 * its events to `<taskId>.events.jsonl`, so a later `apply` re-reads the bytes and
 * can tell whether they are the ones an approval signed. Nothing here writes to
 * the operator's workspace; that is a separate command with a separate gate.
 */
async function runCaseTask(args: string[]): Promise<void> {
  const [contractPath, ...extra] = positionalsOf(args);
  if (!contractPath || extra.length > 0) {
    throw new Error(TASK_USAGE);
  }
  const json = optionsOnly(args);
  const asJson = args.includes('--json');
  const workspace = resolve(json['--workspace'] ?? process.cwd());
  const baseDir = resolve(json['--base-dir'] ?? workspace);
  const allowUnsandboxed = args.includes('--allow-unsandboxed');

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('Set ANTHROPIC_API_KEY in your shell before running a task');

  const contractJson: unknown = JSON.parse(await readFile(contractPath, 'utf8'));
  const report = await runTask(contractJson, {
    workspace,
    baseDir,
    allowUnsandboxed,
    propose: async ({ system, prompt, context }) => {
      const result = await askAnthropic({
        apiKey,
        model: process.env.TERMINAL221B_MODEL ?? defaultModel,
        system,
        prompt,
        context: context || '(The contract named no read refs.)',
      });
      if (!result.ok) {
        // The typed failure becomes a thrown error so the exit code still
        // branches on the kind rather than on prose.
        throw Object.assign(new Error(describeFailure(result.failure)), {
          exitCode: exitCodeFor(result.failure),
        });
      }
      return { patch: patchFromAnswer(result.text) };
    },
  });

  await mkdir(dirname(taskEventsPath(workspace, report.taskId)), { recursive: true });
  await writeFile(candidateDiffPath(workspace, report.taskId), report.patch, 'utf8');
  await appendEvents(taskEventsPath(workspace, report.taskId), report.events);

  if (asJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    console.log(`Task ${report.taskId}: ${report.status}`);
    console.log(`Read set: ${report.readSet.map((item) => item.ref).join(', ') || '(empty)'}`);
    console.log(`Changed paths: ${report.changedPaths.join(', ') || '(none)'}`);
    for (const check of report.checks) {
      console.log(`  check ${check.passed ? 'passed' : `FAILED (exit ${check.status})`}: ${check.check}`);
    }
    for (const failure of report.failures) console.log(`  ${failure}`);
    console.log(`Candidate diff: ${candidateDiffPath(workspace, report.taskId)}`);
    console.log(`Digest: ${report.patchDigest}`);
    console.log(
      report.isolated
        ? 'Isolated: the write set was enforced by the filesystem.'
        : 'NOT ISOLATED: only the path guards applied. F17 stays open for this run.'
    );
  }
  if (report.status !== 'completed') process.exitCode = 1;
}

/**
 * Land a candidate diff. The four gates all live in `applyTaskDiff`; this only
 * reads the bytes off disk so the approval's digest is compared against the file
 * that will actually be written.
 */
async function applyCaseTask(args: string[]): Promise<void> {
  const [contractPath, approvalPath, ...extra] = positionalsOf(args);
  if (!contractPath || !approvalPath || extra.length > 0) {
    throw new Error(TASK_USAGE);
  }
  const json = optionsOnly(args);
  const workspace = resolve(json['--workspace'] ?? process.cwd());
  const storeRoot = resolveStoreRoot(json['--store']);
  const contract = parseTaskContract(JSON.parse(await readFile(contractPath, 'utf8')));
  const approval: unknown = JSON.parse(await readFile(approvalPath, 'utf8'));
  const diff = await readFile(candidateDiffPath(workspace, contract.taskId), 'utf8');

  const paths = await applyTaskDiff({ workspace, storeRoot, contract, patch: diff, approval });
  console.log(`Applied an approved change to ${paths.length} workspace path(s): ${paths.join(', ')}`);
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === '--help' || command === '-h' || !command) {
    printHelp();
    return;
  }
  if (command === 'tools') return showTools();
  if (command === 'tui') return launchTui(args);
  if (command === 'security') {
    if (args[0] !== 'scan') throw new Error('Usage: terminal221b security scan [--workspace PATH]');
    return runSecurityScan(args.slice(1));
  }
  if (command === 'scope') {
    if (args[0] !== 'validate') throw new Error('Usage: terminal221b scope validate PATH');
    return validateScope(args.slice(1));
  }
  if (command === 'case') {
    if (args[0] === 'dossier') return showCaseDossier(args.slice(1));
    if (args[0] === 'template' && args.length === 1) return printCaseTemplate();
    if (args[0] === 'store') return runCaseStore(args.slice(1));
    if (args[0] === 'sign') return signCaseBundle(args.slice(1));
    if (args[0] === 'task' && args[1] === 'run') return runCaseTask(args.slice(2));
    if (args[0] === 'task' && args[1] === 'apply') return applyCaseTask(args.slice(2));
    throw new Error(
      'Usage: terminal221b case dossier PATH [--now ISO8601] [--policy-max-age-days N] [--store DIR] [--json]\n' +
        '       | case template\n' +
        '       | case store init [--store DIR] [--public-key FILE --key-id ID]\n' +
        '       | case store put PATH [--store DIR] [--base-dir DIR] [--entry NAME]\n' +
        '       | case store get ENTRY [--revision N] [--store DIR] [--base-dir DIR]\n' +
        '       | case store verify [--store DIR] [--base-dir DIR]\n' +
        '       | case task run CONTRACT.json [--workspace PATH] [--base-dir DIR] [--json] [--allow-unsandboxed]\n' +
        '       | case task apply CONTRACT.json APPROVAL.json [--workspace PATH] [--store DIR]\n' +
        '       | case sign PATH --key PRIVATE.pem --key-id ID [--signed-at ISO8601]'
    );
  }
  if (command === 'setup') {
    if (args[0] !== 'omarchy') {
      throw new Error('Usage: terminal221b setup omarchy --dry-run');
    }
    return printOmarchyPlan(args.slice(1));
  }
  const cryptoMode = command === 'crypto';
  if (command !== 'ask' && !cryptoMode) throw new Error(`Unknown command: ${command}`);
  if (cryptoMode && args[0] !== 'ask') {
    throw new Error('Usage: terminal221b crypto ask [--workspace PATH] [--apply] PROMPT');
  }
  // `crypto ask` fixes its own profile. Accepting --role here would have to pick
  // between two profiles that both apply, and the quiet options are losing one of
  // them. Refusing is the same rule the rest of this file follows.
  if (cryptoMode && args.slice(1).includes('--role')) {
    throw new Error('--role is not accepted by crypto ask; that command has its own profile');
  }

  const options = parseArgs(cryptoMode ? args.slice(1) : args);
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('Set ANTHROPIC_API_KEY in your shell before using ask');

  const context = await collectWorkspaceContext(options.workspace);
  const contextText = context.files
    .map(({ path, content }) => `--- ${path} ---\n${content}`)
    .join('\n\n');
  console.error(
    `Workspace: ${context.root} (${context.files.length} files, ${context.totalBytes} bytes)`
  );

  // The profile selects the system text. The crypto prohibitions used to travel
  // in the user prompt here while the TUI sent them as a system prompt, so the
  // CLI ran the weaker of two copies that had already drifted. They are system
  // text now, on both sides, from the one clause file.
  //
  // And the role selects the profile. `TaskContract.role` used to be a label no
  // prompt could see; `--role` is where it becomes a parameter, and an ask with
  // no `--role` resolves to the same coding profile it always did.
  const profile: SystemProfile = cryptoMode ? 'crypto' : profileForRole(options.role);
  const instruction = options.apply
    ? `${options.prompt}\nReturn only a unified git diff. Do not include explanations or commands.`
    : options.prompt;
  const result = await askAnthropic({
    apiKey,
    model: process.env.TERMINAL221B_MODEL ?? defaultModel,
    prompt: instruction,
    context: contextText || '(No supported text files found in the workspace.)',
    system: renderSystemPrompt(profile),
    profile,
  });

  if (!result.ok) {
    // Distinct outcomes stay distinct. The exit code branches on the typed kind
    // rather than on a message a caller would have to parse.
    throw Object.assign(new Error(describeFailure(result.failure)), {
      exitCode: exitCodeFor(result.failure),
    });
  }
  const answer = result.text;

  if (!options.apply) {
    console.log(answer);
    return;
  }

  const patch = patchFromAnswer(answer);
  const paths = await applyApprovedPatch(context.root, patch, confirmPatch);
  console.log(`Applied approved changes to ${paths.length} workspace paths.`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown CLI error';
  console.error(`terminal221b: ${message}`);
  // The provider boundary attaches a code per failure kind, so a script can
  // tell a missing key from a 5xx from a cancellation without reading prose.
  const attached = (error as { exitCode?: unknown }).exitCode;
  process.exitCode = typeof attached === 'number' ? attached : 1;
});
