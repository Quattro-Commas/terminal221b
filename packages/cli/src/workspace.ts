import { lstat, readdir, realpath } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { isWithinRoot, readBoundedFile } from './bounded-read.js';

const ignoredDirectories = new Set([
  '.git',
  '.expo',
  '.next',
  '.terminal221b',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'target',
  'vendor',
]);

const textExtensions = new Set([
  '.c',
  '.cc',
  '.cpp',
  '.cs',
  '.css',
  '.go',
  '.h',
  '.hpp',
  '.html',
  '.java',
  '.js',
  '.jsx',
  '.md',
  '.mjs',
  '.mts',
  '.php',
  '.py',
  '.rb',
  '.rs',
  '.scss',
  '.sh',
  '.sol',
  '.sql',
  '.toml',
  '.ts',
  '.tsx',
  '.vue',
  '.vy',
  '.yaml',
  '.yml',
]);

const maxFiles = 80;
const maxFileBytes = 32_000;
const maxTotalBytes = 256_000;

export interface WorkspaceFile {
  path: string;
  content: string;
}

export interface WorkspaceContext {
  root: string;
  files: WorkspaceFile[];
  totalBytes: number;
}

function isIgnoredFile(name: string): boolean {
  return name.startsWith('.') || name === 'package-lock.json' || name === 'pnpm-lock.yaml';
}

export async function collectWorkspaceContext(
  workspacePath: string
): Promise<WorkspaceContext> {
  const root = await realpath(resolve(workspacePath));
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory()) {
    throw new Error('Workspace path must be a directory');
  }

  const files: WorkspaceFile[] = [];
  let totalBytes = 0;

  async function visit(directory: string): Promise<void> {
    if (files.length >= maxFiles || totalBytes >= maxTotalBytes) return;

    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      if (files.length >= maxFiles || totalBytes >= maxTotalBytes) return;
      if (entry.isSymbolicLink()) continue;

      const absolutePath = join(directory, entry.name);
      if (!isWithinRoot(root, absolutePath)) {
        throw new Error('Workspace traversal escaped the selected directory');
      }

      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(absolutePath);
        continue;
      }
      if (!entry.isFile() || isIgnoredFile(entry.name)) continue;
      if (!textExtensions.has(extname(entry.name).toLowerCase())) continue;

      const read = await readBoundedFile(absolutePath, Math.min(maxFileBytes, maxTotalBytes - totalBytes), root);
      if (read.kind === 'skipped') continue;
      const content = read.content;
      if (content.includes('\0')) continue;

      const path = relative(root, absolutePath).split(sep).join('/');
      files.push({ path, content });
      totalBytes += read.bytes; // bytes on disk, not the decoded length
    }
  }

  await visit(root);
  return { root, files, totalBytes };
}
