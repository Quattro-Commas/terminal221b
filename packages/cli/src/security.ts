import { lstat, readdir, realpath } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { readBoundedFile } from './bounded-read.js';

const ignoredDirectories = new Set([
  '.aws',
  '.cache',
  '.expo',
  '.git',
  '.gnupg',
  '.local',
  '.next',
  '.ssh',
  '.terminal221b',
  '.venv',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'target',
  'vendor',
  'venv',
]);

const sourceExtensions = new Set([
  '.c',
  '.cc',
  '.cpp',
  '.cs',
  '.go',
  '.h',
  '.hpp',
  '.java',
  '.js',
  '.jsx',
  '.json',
  '.md',
  '.mjs',
  '.php',
  '.py',
  '.rb',
  '.rs',
  '.sh',
  '.sol',
  '.toml',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);

const secretPatterns: Array<{ id: string; pattern: RegExp }> = [
  { id: 'aws-access-key-id', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'github-token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g },
  { id: 'slack-token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  {
    id: 'private-key-header',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  { id: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

const heuristicPatterns: Array<{
  id: string;
  pattern: RegExp;
  description: string;
}> = [
  {
    id: 'python-shell-true',
    pattern: /\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(.*\bshell\s*=\s*True/,
    description: 'Review shell=True with untrusted input; this is a heuristic, not proof of exploitability.',
  },
  {
    id: 'solidity-tx-origin',
    pattern: /\btx\.origin\b/,
    description: `Heuristic: review authorization based on tx.${'origin'}; this pattern can be legitimate in non-authentication code.`,
  },
];

export interface LocalFinding {
  file: string;
  line: number;
  rule: string;
  severity: 'high' | 'review';
  message: string;
}

export interface LocalScanResult {
  root: string;
  filesScanned: number;
  bytesScanned: number;
  truncated: boolean;
  sourceFiles: string[];
  findings: LocalFinding[];
}

const maxFiles = 10_000;
const maxFileBytes = 1_000_000;
const maxTotalBytes = 16_000_000;

function isWithinRoot(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === '' || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..');
}

function shouldScanFile(name: string): boolean {
  return name.startsWith('.env') || sourceExtensions.has(extname(name).toLowerCase());
}

export async function scanLocalWorkspace(workspacePath: string): Promise<LocalScanResult> {
  const root = await realpath(resolve(workspacePath));
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory()) throw new Error('Workspace path must be a directory');

  const findings: LocalFinding[] = [];
  let filesScanned = 0;
  let bytesScanned = 0;
  let truncated = false;
  const sourceFiles: string[] = [];

  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      if (filesScanned >= maxFiles || bytesScanned >= maxTotalBytes) {
        truncated = true;
        return;
      }
      if (entry.isSymbolicLink()) continue;

      const absolutePath = join(directory, entry.name);
      if (!isWithinRoot(root, absolutePath)) {
        throw new Error('Workspace traversal escaped the selected directory');
      }

      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(absolutePath);
        continue;
      }
      if (!entry.isFile() || !shouldScanFile(entry.name)) continue;

      const read = await readBoundedFile(absolutePath, Math.min(maxFileBytes, maxTotalBytes - bytesScanned), root);
      if (read.kind === 'skipped') {
        if (read.reason === 'too-large') truncated = true;
        continue;
      }
      const content = read.content;
      if (content.includes('\0')) continue;

      const path = relative(root, absolutePath).split(sep).join('/');
      filesScanned += 1;
      bytesScanned += read.bytes; // bytes on disk, not the decoded length
      sourceFiles.push(path);

      for (const [index, line] of content.split(/\r?\n/).entries()) {
        for (const { id, pattern } of secretPatterns) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              file: path,
              line: index + 1,
              rule: id,
              severity: 'high',
              message: 'Possible hard-coded credential pattern; value is hidden. Rotate if real.',
            });
          }
        }
        for (const { id, pattern, description } of heuristicPatterns) {
          if (pattern.test(line)) {
            findings.push({
              file: path,
              line: index + 1,
              rule: id,
              severity: 'review',
              message: description,
            });
          }
        }
      }
    }
  }

  await visit(root);
  return { root, filesScanned, bytesScanned, truncated, sourceFiles, findings };
}
