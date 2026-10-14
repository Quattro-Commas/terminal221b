import type {
  CaseBundle,
  CaseRecord,
  CaseState,
  ClaimType,
  SourceRecord,
  Verification,
} from './case.js';
import { validateCaseBundle } from './case.js';
import {
  evaluateEligibility,
  rankCandidates,
  type BlockReason,
  type CandidateVector,
  type Eligibility,
  type EvaluationOptions,
  type ReviewReason,
} from './ranking.js';

/**
 * Renders the local, offline dossier. Every line is derived from a record in
 * the bundle, so the operator can check each claim against the source digest.
 * No payout estimate, no ranking score, and no network access is involved.
 *
 * Bundle text is untrusted: a claim string is data an operator pasted from
 * somewhere. Every interpolated value is flattened to a single line and stripped
 * of control characters, so a bundle cannot rewrite the terminal, forge a table
 * row, or fake a heading.
 */

const ELIGIBILITY_LABEL: Record<CandidateVector['eligibility'], string> = {
  eligible: 'ELIGIBLE',
  review: 'REVIEW',
  blocked: 'BLOCKED',
  not_evaluated: 'NOT EVALUATED',
};

const LINE_BREAKS = /[\r\n\u2028\u2029]+/g;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/g;

function safe(value: string): string {
  return value.replace(LINE_BREAKS, ' ').replace(CONTROL_CHARACTERS, '\ufffd');
}

/** A markdown table cell: backslashes escaped first, so text ending in one cannot
 * un-escape the pipe that follows and split the cell. */
export function safeCell(value: string): string {
  return safe(value).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/**
 * The one operator question this surface answers, in one place, beside
 * {@link WHAT_THIS_DOES_NOT_DO} and for the same reason.
 *
 * It used to live only in `packages/rust-tui/src/dossier.rs`, as a Rust
 * constant. That is finding F23 exactly: a shared boundary held by two readers
 * of one file is a convention, not a check. The markdown export had no
 * equivalent, so the question the screen claims to answer was invisible to
 * anyone who exported the dossier. Both renderers now read this one value, and
 * `packages/cli/tests/dossier.test.ts` fails if the Rust side grows its own copy.
 */
export const OPERATOR_QUESTION =
  'Which cases are actionable, why is each other one held, and what would unblock it?';

/**
 * The boundary statement, in one place, because two renderers read it.
 *
 * `renderDossier` prints it as markdown and `dossierReport` carries it as data
 * for the terminal screen, so the screen cannot grow a claim the markdown does
 * not make. That is the whole reason it is a const and not two lists.
 */
export const WHAT_THIS_DOES_NOT_DO: readonly string[] = [
  'it does not contact a target, submit anything, or hold signing keys',
  'it does not estimate reward size, payout odds, or an overall score',
  'it does not verify a policy snapshot; the recorded timestamp is taken on trust',
  'a case reaches the actionable queue only with a human confirmation pinned to one exact asset and one exact policy snapshot, carrying a signature that verifies against a key a case store trusts',
  'without a --store it cannot check any signature, so a confirmed case is reported as awaiting one rather than as queued',
  'a signature proves who held the key, not which person typed it, and a local source digest proves the bytes did not change, not that the remote original was ever fetched',
  'a fact claim only appears here with deterministic or operator-confirmed verification',
];

function assetLine(item: CaseRecord): string {
  if (item.asset.status === 'exact') return safe(item.asset.canonical);
  if (item.asset.status === 'wildcard') {
    return `${safe(item.asset.pattern)} (wildcard; a pattern is never treated as an asset)`;
  }
  return `${safe(item.assetOriginal)} (ambiguous: ${safe(item.asset.reason)})`;
}

function section(title: string): string[] {
  return [`## ${title}`, ''];
}

function factorTable(vector: CandidateVector): string[] {
  return [
    '| factor | level | basis | reference |',
    '| --- | --- | --- | --- |',
    ...Object.entries(vector.factors).map(
      ([factor, value]) =>
        `| ${factor} | ${value.level} | ${safeCell(value.basis)} | ${safeCell(value.refId ?? '-')} |`
    ),
  ];
}

export function renderDossier(bundle: CaseBundle, options: EvaluationOptions): string {
  const problems = validateCaseBundle(bundle);
  const vectors = rankCandidates(bundle, options);
  const byId = new Map(vectors.map((item) => [item.caseId, item]));

  const lines: string[] = [
    '# Case dossier',
    '',
    `Question this dossier answers: ${safe(OPERATOR_QUESTION)}`,
    '',
    `Evaluated at ${options.now} with a policy freshness limit of ${options.policyMaxAgeDays} days.`,
    'Local and offline: nothing was requested from a target, and no payout is estimated.',
    'Freshness is measured from an operator-recorded snapshot timestamp, not from anything verified here.',
    '',
  ];

  lines.push(...section('Provenance'));
  if (problems.length === 0) {
    lines.push('All records link: every case, evidence, task, approval, and outcome resolves.', '');
  } else {
    lines.push('Unresolved links:', '');
    lines.push(...problems.map((problem) => `- ${safe(problem)}`), '');
  }

  lines.push(...section('Actionable queue (ELIGIBLE only)'));
  const eligible = vectors.filter((item) => item.eligibility === 'eligible');
  if (eligible.length === 0) {
    lines.push('No case is currently eligible for owner review.', '');
  } else {
    eligible.forEach((item) => {
      lines.push(`${item.rank + 1}. ${item.caseId} (${item.factors.evidence_quality.level} evidence quality)`);
    });
    lines.push('');
  }

  lines.push(...section('Cases'));
  for (const item of bundle.cases) {
    const vector = byId.get(item.caseId);
    if (!vector) continue;
    const gate: string[] = [];
    if (vector.reasons.length > 0) gate.push(`blocked: ${vector.reasons.join(', ')}`);
    if (vector.reviewReasons.length > 0) gate.push(`awaiting operator: ${vector.reviewReasons.join(', ')}`);
    const snapshot = bundle.sources.find((entry) => entry.sourceId === item.policySnapshotId);
    const version = snapshot?.policyVersion ? ` (version ${safe(snapshot.policyVersion)})` : '';
    lines.push(
      `### ${safe(item.caseId)} — ${ELIGIBILITY_LABEL[vector.eligibility]}`,
      '',
      `- objective: ${safe(item.objective)}`,
      `- program: ${safe(item.programId)}`,
      `- asset: ${assetLine(item)}`,
      `- asset type: ${safe(item.assetType)}`,
      `- state: ${item.state}`,
      `- policy snapshot: ${safe(item.policySnapshotId)}${version}${
        gate.length > 0 ? ` (${gate.join('; ')})` : ''
      }`,
      ''
    );
    if (vector.notEvaluatedReason) {
      lines.push(`Evaluation failed: ${safe(vector.notEvaluatedReason)}`, '');
    }
    lines.push(...factorTable(vector), '');
    if (vector.assessmentNotes.length > 0) {
      lines.push('Assessments not applied:', '');
      lines.push(...vector.assessmentNotes.map((note) => `- ${safe(note)}`), '');
    }

    const evidence = bundle.evidence.filter((claim) => claim.caseId === item.caseId);
    if (evidence.length > 0) {
      lines.push('Evidence:', '');
      for (const claim of evidence) {
        lines.push(
          `- [${claim.claimType}/${claim.verification}] ${safe(claim.claim)} (${safe(claim.evidenceId)}, source ${safe(claim.sourceId)})`
        );
      }
      lines.push('');
    }

    const confirmations = bundle.confirmations.filter((entry) => entry.caseId === item.caseId);
    for (const confirmation of confirmations) {
      lines.push(
        `Confirmation ${safe(confirmation.confirmationId)}: human, ${safe(confirmation.confirmedAt)} — ${safe(confirmation.statement)} (pinned to ${safe(confirmation.asset)} against ${safe(confirmation.policySnapshotId)})`,
        ''
      );
    }

    const searches = bundle.duplicateSearches.filter((entry) => entry.caseId === item.caseId);
    for (const search of searches) {
      const matches = search.matchedCaseIds.length > 0 ? search.matchedCaseIds.join(', ') : 'nothing';
      lines.push(
        `Duplicate search ${safe(search.searchId)}: covered ${safe(search.surfaceCovered)}, matched ${safe(matches)} — ${safe(search.similarityCaveat)}`,
        ''
      );
    }

    const assessments = bundle.assessments.filter((entry) => entry.caseId === item.caseId);
    for (const assessment of assessments) {
      lines.push(
        `Assessment ${safe(assessment.assessmentId)}: ${assessment.factor} = ${assessment.level} (ref ${safe(assessment.refId)}) — ${safe(assessment.basis)}`,
        ''
      );
    }

    const approvals = bundle.approvals.filter((item2) => item2.caseId === item.caseId);
    for (const approval of approvals) {
      lines.push(`Approval ${safe(approval.approvalId)}: ${approval.decision} by human — ${safe(approval.effect)}`, '');
    }

    const outcomes = bundle.outcomes.filter((item2) => item2.caseId === item.caseId);
    for (const outcome of outcomes) {
      const cost = outcome.actualCostUsd
        ? `; cost ${outcome.actualCostUsd.amount} USD (${outcome.actualCostUsd.source})`
        : '';
      const receipt = outcome.receiptReference ? `; receipt ${safe(outcome.receiptReference)}` : '';
      lines.push(`Outcome ${safe(outcome.outcomeId)}: ${outcome.disposition}${receipt}${cost}`, '');
    }
  }

  const programs = bundle.programs;
  if (programs.length > 0) {
    lines.push(...section('Program material (as published)'));
    for (const program of programs) {
      lines.push(
        `### ${safe(program.programId)}`,
        '',
        `- published reward schedule: ${safe(program.rewardSchedulePublished)}`,
        `- published categories: ${program.rewardCategoriesPublished.map(safe).join(', ') || '-'}`,
        `- bounty asset types: ${program.bountyAssetTypes.map(safe).join(', ') || '-'}`,
        `- report requirements: ${program.reportRequirements.map(safe).join('; ') || '-'}`,
        `- testing constraints: ${program.testingConstraints.map(safe).join('; ') || '-'}`,
        ''
      );
    }
  }

  lines.push(
    ...section('What this dossier does not do'),
    ...WHAT_THIS_DOES_NOT_DO.map((line) => `- ${line}`),
    ''
  );

  return `${lines.join('\n')}`;
}

/**
 * The machine-readable half of the dossier.
 *
 * The terminal screen in `packages/rust-tui` displays these words; it does not
 * decide them. That division is the point: a second implementation of the
 * eligibility gate in Rust would drift from this one, and a drifted gate is a
 * security surface, not a convenience. So the gate is computed exactly once,
 * here, and the screen is a reader.
 *
 * Every field is either recomputed by this module or copied out of the bundle.
 * Nothing is invented, and the one place where a value is *declared* rather than
 * verified is typed as the literal `'declared'`, so this module cannot claim a
 * digest it did not check.
 */

/** Which trust decision the gate was given. The screen shows it as a word. */
export type SignatureTrust = 'trusted-store' | 'no-store';

export interface DossierAsset {
  status: 'exact' | 'wildcard' | 'ambiguous';
  /** Exactly as intake reported it, ambiguity and all. */
  original: string;
  canonical?: string;
  pattern?: string;
  reason?: string;
}

export interface DossierSource {
  sourceId: string;
  uri: string;
  observedAt: string;
  policyVersion?: string;
  contentDigest: string;
  /**
   * Always `'declared'`. The case store re-hashes local bytes before it accepts
   * a bundle; this renderer reads a bundle and touches no source bytes at all,
   * so a digest here is the bundle's own claim about itself (F16).
   */
  digestStatus: 'declared';
}

export interface DossierConfirmation {
  confirmationId: string;
  confirmedAt: string;
  asset: string;
  policySnapshotId: string;
  statement: string;
  /**
   * Whether the record carries an attestation at all. The gate, not this field,
   * decides whether that attestation *verifies*; a true here is not a signature
   * check (F15).
   */
  signed: boolean;
  keyId?: string;
}

export interface DossierEvidence {
  evidenceId: string;
  claim: string;
  claimType: ClaimType;
  verification: Verification;
  sourceId: string;
  observedAt: string;
}

export interface DossierCase {
  /** -1 when the case was not evaluated, so an unevaluated case never outranks one that was. */
  rank: number;
  caseId: string;
  objective: string;
  programId: string;
  asset: DossierAsset;
  assetType: string;
  state: CaseState;
  policySnapshotId: string;
  policyVersion?: string;
  /** Recomputed here from the operator-recorded observedAt; null when no snapshot resolves. */
  policyAgeDays: number | null;
  policyMaxAgeDays: number;
  eligibility: Eligibility;
  blocked: BlockReason[];
  /** Empty for an eligible or blocked case. A review is a queue, not a verdict. */
  awaiting: ReviewReason[];
  /** Set when evaluation itself failed, so the failure is visible rather than silent. */
  notEvaluatedReason?: string;
  confirmations: DossierConfirmation[];
  evidence: DossierEvidence[];
}

export interface DossierReport {
  version: 2;
  /**
   * The operator question, carried as data so the terminal screen and the
   * markdown export answer the same question. Required, not optional: a report
   * that omits it is a report some screen is not being shown what it answers.
   */
  operatorQuestion: string;
  now: string;
  policyMaxAgeDays: number;
  signatureTrust: SignatureTrust;
  storeRoot?: string;
  provenance: { ok: boolean; problems: string[] };
  cases: DossierCase[];
  sources: DossierSource[];
  notDoing: string[];
}

export interface DossierReportContext {
  signatureTrust: SignatureTrust;
  storeRoot?: string;
}

function assetFor(item: CaseRecord): DossierAsset {
  const original = safe(item.assetOriginal);
  if (item.asset.status === 'exact') {
    return { status: 'exact', original, canonical: item.asset.canonical };
  }
  if (item.asset.status === 'wildcard') {
    return { status: 'wildcard', original, pattern: item.asset.pattern };
  }
  return { status: 'ambiguous', original, reason: safe(item.asset.reason) };
}

function sourceFor(entry: SourceRecord): DossierSource {
  return {
    sourceId: entry.sourceId,
    uri: safe(entry.uri),
    observedAt: entry.observedAt,
    ...(entry.policyVersion === undefined ? {} : { policyVersion: safe(entry.policyVersion) }),
    contentDigest: entry.contentDigest,
    digestStatus: 'declared' as const,
  };
}

/**
 * The age is read from the same `evaluateEligibility` call `evaluateCandidate`
 * makes, not recomputed here. A second age calculation would be a second gate,
 * and a gate that disagrees with itself is worse than no gate.
 */
function policyAgeFor(
  item: CaseRecord,
  bundle: CaseBundle,
  options: EvaluationOptions
): number | null {
  try {
    return evaluateEligibility(item, bundle, options).policyAgeDays;
  } catch {
    // The vector already carries `not_evaluated` plus the reason. An absent age
    // is the honest rendering of a case that could not be evaluated at all.
    return null;
  }
}

/**
 * Projects the bundle and the gate's own output into a shape a terminal can
 * render. Pure: it reads nothing, fetches nothing, and writes nothing.
 */
export function dossierReport(
  bundle: CaseBundle,
  options: EvaluationOptions,
  context: DossierReportContext
): DossierReport {
  const problems = validateCaseBundle(bundle);
  const vectors = rankCandidates(bundle, options);
  const byId = new Map(vectors.map((item) => [item.caseId, item]));

  const cases: DossierCase[] = bundle.cases.map((item) => {
    const vector: CandidateVector | undefined = byId.get(item.caseId);
    const snapshot = bundle.sources.find((entry) => entry.sourceId === item.policySnapshotId);
    return {
      // A case whose evaluation failed is not ranked, and says so.
      rank: vector?.rank ?? -1,
      caseId: safe(item.caseId),
      objective: safe(item.objective),
      programId: safe(item.programId),
      asset: assetFor(item),
      assetType: safe(item.assetType),
      state: item.state,
      policySnapshotId: safe(item.policySnapshotId),
      ...(snapshot?.policyVersion === undefined
        ? {}
        : { policyVersion: safe(snapshot.policyVersion) }),
      policyAgeDays: policyAgeFor(item, bundle, options),
      policyMaxAgeDays: options.policyMaxAgeDays,
      eligibility: vector?.eligibility ?? 'not_evaluated',
      blocked: vector?.reasons ?? [],
      awaiting: vector?.reviewReasons ?? [],
      ...(vector?.notEvaluatedReason === undefined
        ? {}
        : { notEvaluatedReason: safe(vector.notEvaluatedReason) }),
      confirmations: bundle.confirmations
        .filter((entry) => entry.caseId === item.caseId)
        .map((entry) => ({
          confirmationId: safe(entry.confirmationId),
          confirmedAt: entry.confirmedAt,
          asset: safe(entry.asset),
          policySnapshotId: safe(entry.policySnapshotId),
          statement: safe(entry.statement),
          signed: entry.attestation !== undefined,
          ...(entry.attestation === undefined ? {} : { keyId: safe(entry.attestation.keyId) }),
        })),
      evidence: bundle.evidence
        .filter((claim) => claim.caseId === item.caseId)
        .map((claim) => ({
          evidenceId: safe(claim.evidenceId),
          claim: safe(claim.claim),
          claimType: claim.claimType,
          verification: claim.verification,
          sourceId: safe(claim.sourceId),
          observedAt: claim.observedAt,
        })),
    };
  });

  return {
    version: 2,
    operatorQuestion: OPERATOR_QUESTION,
    now: options.now,
    policyMaxAgeDays: options.policyMaxAgeDays,
    signatureTrust: context.signatureTrust,
    ...(context.storeRoot === undefined ? {} : { storeRoot: context.storeRoot }),
    provenance: { ok: problems.length === 0, problems: problems.map(safe) },
    cases,
    sources: bundle.sources.map(sourceFor),
    notDoing: [...WHAT_THIS_DOES_NOT_DO],
  };
}
