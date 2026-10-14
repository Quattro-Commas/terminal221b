// Child process for store-stress.test.ts: <compiledDir> <root> <bundle.json> <baseDir> <count>
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [compiledDir, root, bundlePath, baseDir, count] = process.argv.slice(2);
const store = await import(pathToFileURL(join(compiledDir, 'store.js')).href);
const kase = await import(pathToFileURL(join(compiledDir, 'case.js')).href);
const bundle = kase.parseCaseBundle(JSON.parse(readFileSync(bundlePath, 'utf8')));
const revisions = [];
for (let i = 0; i < Number(count); i += 1) {
  const result = await store.putBundle(root, bundle, { now: '2026-09-30T12:00:00Z', baseDir });
  revisions.push(result.revision);
}
process.stdout.write(JSON.stringify(revisions));
