/**
 * The case file as a MITRE ATT&CK Navigator layer.
 *
 * A layer is the interchange format of this corner of the trade: a JSON file
 * that colours and scores techniques on the matrix, which Navigator opens,
 * diffs against another layer, and combines with score expressions. Exporting
 * one means the coverage picture leaves this tool without anybody retyping
 * technique IDs into a second one.
 *
 * The thing a layer shows that a spreadsheet cannot is the verdict. A technique
 * somebody confirmed and a technique the model proposed and nobody has looked
 * at yet are different claims, and a coverage map that colours them alike
 * overstates what is known — which is the direction that gets somebody hurt.
 */

/** Scores, not booleans, because the gradient is what carries the distinction. */
const SCORE = { filed: 3, pending: 1 };

/*
  Free text, typed by an analyst under time pressure. The same technique arrives
  as "T1053.005", as "T1053.005 — Scheduled Task", as two IDs in one cell, and
  in lower case. Pulling the IDs out is the whole reason this is not a straight
  column read: a layer built by trusting the cell shows one technique per
  spelling and none of them line up with the matrix.
*/
const TECHNIQUE = /\bT\d{4}(?:\.\d{3})?\b/gi;

export const techniqueIds = (cell) =>
  [...String(cell ?? '').matchAll(TECHNIQUE)].map(m => m[0].toUpperCase());

/**
 * @param records  records as the store returns them
 * @param options  name/description for the layer header
 */
export function recordsToNavigatorLayer(records = [], {
  name = 'Hunt findings',
  description = 'Techniques carried by the findings in this case file.',
  generatedAt = new Date().toISOString(),
} = {}) {
  /*
    Denied records are dropped rather than scored zero. A denial is a statement
    that the technique was not observed here, and drawing it on the matrix at
    all invites it to be read as thin coverage rather than as a closed question.
  */
  const scored = new Map();
  for (const r of records) {
    const score = SCORE[r.state];
    if (!score) continue;
    for (const id of techniqueIds(r.mitre)) {
      const prev = scored.get(id) ?? { score: 0, from: [] };
      // The strongest verdict wins: one confirmation is not weakened by
      // however many proposals sit behind it.
      prev.score = Math.max(prev.score, score);
      prev.from.push(r.event_id || r.id);
      scored.set(id, prev);
    }
  }

  const techniques = [...scored.entries()].map(([techniqueID, v]) => ({
    techniqueID,
    score: v.score,
    // Traceability is the point. A layer nobody can walk back to the evidence
    // is a picture, and this tool exists because pictures are not verdicts.
    comment: `${v.from.length} record${v.from.length === 1 ? '' : 's'}: ${v.from.join(', ')}`,
    enabled: true,
    showSubtechniques: techniqueID.includes('.'),
    metadata: [],
    links: [],
  }));

  return {
    name,
    versions: { layer: '4.5', navigator: '4.9.0', attack: '14' },
    domain: 'enterprise-attack',
    description: `${description} Generated ${generatedAt}.`,
    techniques,
    gradient: {
      // Low to high, so an unadjudicated proposal reads as paler than a call.
      colors: ['#ffe0b2', '#e65100'],
      minValue: 0,
      maxValue: SCORE.filed,
    },
    legendItems: [
      { label: `Confirmed (${SCORE.filed})`, color: '#e65100' },
      { label: `Proposed, not yet adjudicated (${SCORE.pending})`, color: '#ffe0b2' },
    ],
    showTacticRowBackground: true,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    sorting: 3,
    hideDisabled: false,
    layout: { layout: 'side', showID: true, showName: true },
  };
}
