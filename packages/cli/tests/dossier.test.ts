import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  dossierReport,
  OPERATOR_QUESTION,
  renderDossier,
  type DossierReport,
  type DossierReportContext,
} from '../src/dossier.js';
import { signBundle } from '../src/store.js';
import { FIXTURE_NOW, FIXTURE_POLICY_MAX_AGE_DAYS, fixtureBundle } from '../src/case-fixtures.js';

/**
 * The report is a contract between two implementations: this file writes it and
 * `packages/rust-tui/src/dossier.rs` reads it. A field renamed on one side and
 * not the other is the same failure as F22, where the crypto clause set drifted
 * between the CLI and the TUI — except here the drift would be silent, because
 * a Rust struct with a missing field simply stops reading that value.
 *
 * So two tests do the work. One pins the markdown renderer, which is the
 * operator-facing output that already existed and must not move. The other reads
 * the Rust source and asserts every field it declares is a key this side
 * actually emits, in both directions, and fails if either list is empty.
 */

const RUST_SOURCE = join(
  process.cwd(),
  'packages/rust-tui/src/dossier.rs'
);

const OPTIONS = { now: FIXTURE_NOW, policyMaxAgeDays: FIXTURE_POLICY_MAX_AGE_DAYS };
const NO_STORE: DossierReportContext = { signatureTrust: 'no-store' };

function reportFor(context: DossierReportContext = NO_STORE): DossierReport {
  return dossierReport(fixtureBundle, OPTIONS, context);
}

/** The digest of the markdown the dossier printed before `--json` existed. */
// Pinned on 2026-10-02, deliberately moved. The previous value
// 9b0a9c64ba5158239d1b6eb2d5853097e173207caaf984fa973f1a8398069a87 was the
// Slice 5 baseline. The markdown now opens with the operator question, because
// the question lived only in Rust and this export answered a question it never
// stated (F23). Nothing else in the rendering changed.
const RENDERED_MARKDOWN_SHA256 = '76897406cf79c502fb256ecb80f1d64c1fe68cb319d38fbc4efb847db8226d5f';

describe('the report the TUI reads is a stated contract, not an accident', () => {
  it('carries the version the screen checks before it trusts anything', () => {
    // 2, not 1: version 2 is what carries `operatorQuestion`. A screen still
    // expecting 1 refuses a report rather than drawing an empty row, which is
    // the intended behaviour of a contract change and is asserted in the Rust
    // `parse_report` tests.
    expect(reportFor().version).toBe(2);
  });

  it('carries the operator question so the screen and this export agree on it', () => {
    const report = reportFor();
    expect(report.operatorQuestion).toBe(OPERATOR_QUESTION);
    expect(report.operatorQuestion.endsWith('?')).toBe(true);
  });

  it('names its evaluation moment and the policy limit that was applied', () => {
    const report = reportFor();
    expect(report.now).toBe(FIXTURE_NOW);
    expect(report.policyMaxAgeDays).toBe(FIXTURE_POLICY_MAX_AGE_DAYS);
  });

  it('states whether signatures were checked and against what', () => {
    expect(reportFor({ signatureTrust: 'no-store' }).signatureTrust).toBe('no-store');
    expect(reportFor({ signatureTrust: 'no-store' }).storeRoot).toBeUndefined();
    const trusted = reportFor({
      signatureTrust: 'trusted-store',
      storeRoot: '/home/operator/.local/share/terminal221b',
    });
    expect(trusted.signatureTrust).toBe('trusted-store');
    expect(trusted.storeRoot).toBe('/home/operator/.local/share/terminal221b');
  });

  it('reports the provenance result rather than assuming it', () => {
    const report = reportFor();
    expect(report.provenance.ok).toBe(true);
    expect(report.provenance.problems).toEqual([]);
  });

  it('gives every case a decision, and an unevaluated case a reason', () => {
    const report = reportFor();
    expect(report.cases.length).toBeGreaterThan(0);
    for (const item of report.cases) {
      expect(['eligible', 'review', 'blocked', 'not_evaluated']).toContain(item.eligibility);
      expect(item.policyMaxAgeDays).toBe(FIXTURE_POLICY_MAX_AGE_DAYS);
      if (item.eligibility === 'not_evaluated') {
        expect(item.notEvaluatedReason, `${item.caseId} has no reason`).toBeTruthy();
      }
      // A held case must say what holds it. A REVIEW with an empty reason list
      // is the failure this guards: the screen would render "actionable".
      if (item.eligibility === 'review' || item.eligibility === 'blocked') {
        expect(
          item.awaiting.length + item.blocked.length,
          `${item.caseId} is ${item.eligibility} and says nothing`
        ).toBeGreaterThan(0);
      }
    }
  });

  it('marks every source digest as declared, because the gate never re-read it', () => {
    // This is the F16 shape: `digestStatus` is typed as the literal 'declared',
    // so this side cannot compile a claim it did not check, and the Rust side
    // can only decode 'declared'. See the drift test below.
    const report = reportFor();
    expect(report.sources.length).toBeGreaterThan(0);
    for (const source of report.sources) {
      expect(source.digestStatus).toBe('declared');
      expect(source.contentDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });

  it('reports the same boundary the markdown renderer prints', () => {
    const report = reportFor();
    expect(report.notDoing.length).toBeGreaterThan(0);
    for (const line of report.notDoing) {
      expect(renderDossier(fixtureBundle, OPTIONS)).toContain(line);
    }
  });

  it('numbers a rank only for an actionable case', () => {
    for (const item of reportFor().cases) {
      if (item.eligibility === 'eligible') {
        expect(item.rank, `${item.caseId} is eligible but unranked`).toBeGreaterThanOrEqual(0);
      } else {
        expect(item.rank, `${item.caseId} is not eligible but is ranked`).toBe(-1);
      }
    }
  });

  it('reads nothing: the same bundle and clock give the same report', () => {
    expect(JSON.stringify(reportFor())).toBe(JSON.stringify(reportFor()));
  });
});

describe('adding --json changed nothing anyone was already reading', () => {
  it('the markdown is byte-for-byte what it was before the report existed', () => {
    const text = renderDossier(fixtureBundle, OPTIONS);
    expect(createHash('sha256').update(text).digest('hex')).toBe(RENDERED_MARKDOWN_SHA256);
  });

  it('and the control: the digest is measured from the bytes under test', () => {
    // A digest compared against itself proves nothing, so this asserts the
    // renderer is deterministic and the constant above is not a stale literal.
    const first = renderDossier(fixtureBundle, OPTIONS);
    const second = renderDossier(fixtureBundle, OPTIONS);
    expect(first).toBe(second);
    expect(first.length).toBeGreaterThan(1000);
  });
});

describe('the two implementations of this contract are held together', () => {
  const rust = readFileSync(RUST_SOURCE, 'utf8');

  it('the control: the Rust source was found and declares the structs', () => {
    expect(rust.length).toBeGreaterThan(1000);
    expect(rust).toContain('pub struct Report');
    expect(rust).toContain('#[serde(rename_all = "camelCase")]');
  });

  it('every field the Rust screen declares is a key this side emits somewhere', () => {
    // Optional fields are why this is a union over every instance rather than a
    // check on one: `store_root` is absent until a store is named, `key_id` is
    // absent until a confirmation is signed. A field that appears in no
    // instance, and is not on the named `neverExercised` list, is the drift.
    const emitted = emittedKeys();
    const declared = wireStructs(rust);
    const missing = [...declared.entries()]
      .map(([structName, keys]) =>
        keys
          .filter((key) => !emitted.get(structName)?.has(key) && !neverExercised.has(`${structName}.${key}`))
          .map((key) => `${structName}.${key}`)
      )
      .flat();
    expect(missing).toEqual([]);
    expect([...emitted.values()].reduce((total, keys) => total + keys.size, 0)).toBeGreaterThan(20);
  });

  it('every key this side emits is declared on the Rust side, in both directions', () => {
    // The other direction, per struct. A field added here and not there would
    // be dropped silently by serde, so the screen would simply not show it.
    const emitted = emittedKeys();
    const declared = wireStructs(rust);
    const undeclared: string[] = [];
    for (const [structName, keys] of emitted) {
      if (!notDeclaredOnPurpose.has(structName)) {
        const known = new Set(declared.get(structName) ?? []);
        for (const key of keys) {
          if (!known.has(key)) {
            undeclared.push(`${structName}.${key}`);
          }
        }
      }
    }
    expect(undeclared).toEqual([]);
  });

  it('the operator question lives here and not in the Rust screen', () => {
    // F23: a boundary held by two readers of one file is a convention, not a
    // check. The question was a Rust constant and this export never stated it,
    // so the screen answered a question the export could not show anyone. It is
    // now payload, and a second copy on the Rust side would reintroduce the
    // drift with nothing failing — which is what this catches.
    //
    // Asserted against the declaration, not the bare name: this comment names
    // it, so matching the name alone would always find a hit.
    expect(rust).not.toContain('const OPERATOR_QUESTION');
    expect(rust).not.toContain('OPERATOR_QUESTION: &str');
    expect(rust).toContain('operator_question');
    expect(rust).toContain('report.operator_question');
  });

  it('the allow-lists still name fields this side really has', () => {
    // A control, so neither list can rot into a rubber stamp.
    const source = readFileSync(join(process.cwd(), 'packages/cli/src/dossier.ts'), 'utf8');
    for (const entry of neverExercised) {
      const field = entry.split('.').pop() as string;
      expect(source, `${entry} is allow-listed but absent from dossier.ts`).toContain(field);
    }
    expect(notDeclaredOnPurpose.size).toBeGreaterThan(0);
    expect(emittedKeys().size).toBe(WIRE_STRUCTS.length);
  });
});

/** The Rust structs that are deserialized from this side's JSON. `Row` and
 * `View` are rendering types and never see the wire, so they are excluded and
 * the last test asserts this list is fully exercised. */
const WIRE_STRUCTS = ['Report', 'Provenance', 'Asset', 'Source', 'Confirmation', 'Evidence', 'Case'];

/** `Report` carries fields the markdown renderer reads and the screen does not
 * show; the rest are compared key for key. Named so a new omission is a failure. */
const notDeclaredOnPurpose = new Set(['Report']);

function wireStructs(source: string): Map<string, string[]> {
  const all = rustFieldNames(source);
  return new Map(WIRE_STRUCTS.map((name) => [name, all.get(name) ?? []]).filter(([, keys]) => keys.length > 0));
}

/**
 * Rust fields this bundle never exercises. `notEvaluatedReason` needs a case the
 * gate could not evaluate, and the fixture bundle has none, so the field's
 * presence on the wire is asserted in `dossier.rs` on the Rust side instead.
 */
const neverExercised = new Set(['Case.notEvaluatedReason']);

/**
 * The keys each wire struct carries, across every instance and every trust
 * shape. Signing the fixture matters: `keyId` only appears on a confirmation
 * that carries an attestation, so a report built from an unsigned bundle would
 * leave a declared Rust field looking undeclared.
 */
function emittedKeys(): Map<string, Set<string>> {
  // Signed in process, with a throwaway key. `keyId` only reaches the wire when
  // a confirmation carries an attestation, so an unsigned-only report would make
  // a declared Rust field look undeclared and the guard would be lying.
  const { privateKey } = generateKeyPairSync('ed25519');
  const signed = signBundle(fixtureBundle, privateKey, 'guard-key', FIXTURE_NOW);
  const reports = [
    reportFor(NO_STORE),
    reportFor({ signatureTrust: 'trusted-store', storeRoot: '/tmp/store' }),
    dossierReport(
      signed,
      { ...OPTIONS, confirmationSigned: () => true },
      { signatureTrust: 'trusted-store', storeRoot: '/tmp/store' }
    ),
  ];
  const keys = new Map<string, Set<string>>();
  const record = (structName: string, value: unknown): void => {
    let found = keys.get(structName);
    if (!found) {
      found = new Set<string>();
      keys.set(structName, found);
    }
    if (Array.isArray(value)) {
      value.forEach((entry) => record(structName, entry));
      return;
    }
    if (value && typeof value === 'object') {
      for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
        found.add(key);
        if (key === 'provenance') record('Provenance', entry);
        if (key === 'asset') record('Asset', entry);
        if (key === 'confirmations') record('Confirmation', entry);
        if (key === 'evidence') record('Evidence', entry);
      }
    }
  };
  for (const report of reports) {
    record('Report', report);
    record('Source', report.sources);
    record('Case', report.cases);
  }
  return keys;
}

/** `#[serde(rename_all = "camelCase")]` means the wire name is the field name
 * with underscores removed and the first letter lower-cased. */
function camel(field: string): string {
  const head = field.split('_')[0] ?? field;
  const tail = field.slice(head.length).replace(/_([a-z])/g, (_all, letter: string) => letter.toUpperCase());
  return `${head}${tail}`;
}

/** The `pub` fields of each `pub struct` in the Rust source, as wire names. */
function rustFieldNames(source: string): Map<string, string[]> {
  const found = new Map<string, string[]>();
  const structPattern = /pub struct (\w+) \{([\s\S]*?)\n\}/g;
  for (const match of source.matchAll(structPattern)) {
    const name = match[1];
    const body = match[2] ?? '';
    const fields = [...body.matchAll(/pub (\w+):/g)].map((field) => camel(field[1] as string));
    if (fields.length > 0) {
      found.set(name, fields);
    }
  }
  return found;
}



describe('table cells cannot be broken by their own text', () => {
  // GitHub-flavoured markdown ends a cell at a pipe not escaped by an odd run of backslashes.
  const cellBreaks = (row: string): number => {
    let breaks = 0;
    for (let i = 0; i < row.length; i += 1) {
      if (row[i] !== '|') continue;
      let slashes = 0;
      for (let j = i - 1; j >= 0 && row[j] === '\\'; j -= 1) slashes += 1;
      if (slashes % 2 === 0) breaks += 1;
    }
    return breaks;
  };

  it.each(['plain', 'a|b', 'x\\|y', 'ends with \\', '\\\\|', 'many \\\\\\| here'])(
    'keeps %j in one cell',
    async (value) => {
      const { safeCell } = await import('../src/dossier.js');
      expect(cellBreaks(`| ${safeCell(value)} |`)).toBe(2);
    }
  );
});
