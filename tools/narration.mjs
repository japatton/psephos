/**
 * Narration for the demo recordings: what gets said, when, and the subtitles.
 *
 * macOS speaks it — `say` is in the box, the Premium voices are free and
 * offline, and a recording of a tool whose whole argument is that it installs
 * nothing should not need a cloud API to have a voice.
 *
 * Synthesised BEFORE anything is filmed, because the picture follows the voice
 * rather than the other way round: each line's real duration is what the shot
 * is held for. Aligning afterwards means either trimming the video or speeding
 * up the speech, and both are audible.
 *
 * Its own module because the scheduling is the part that can be wrong quietly —
 * a subtitle out of step with the voice survives every take unless something
 * checks it. See test/narration.test.js.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

/** Strip the caption's markup — <b> is cyan on screen and nothing to the ear. */
export const stripped = (caption) =>
  caption.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();

/*
  What to feed the synthesiser where the spelling defeats it.

  The subtitle keeps the real spelling; only the voice gets these. The rule
  behind the list: no identifier, no technique number, no roster surname and no
  hyphenated compound is ever spoken — where one was needed, the line was
  rewritten instead of fought, which is why this table is short.
*/
export const SAY_AS = [
  [/\bPsephos\b/g, 'Seefoss'],
  [/ATT&CK/g, 'attack'],
  [/\bCLI\b/g, 'C L I'],
  [/\bAPI\b/g, 'A P I'],
  [/\bcron\b/g, 'kron'],
  [/\bgitignored\b/g, 'git ignored'],
  [/owner-only/g, 'owner only'],
  [/mid-hunt/g, 'mid hunt'],
];
export const spoken = (caption) =>
  SAY_AS.reduce((t, [re, to]) => t.replace(re, to), stripped(caption));

/**
 * Speak every line and measure it.
 * @returns Map of caption text -> { file, ms }
 */
export async function synthesise(lines, { voice, dir, rate }) {
  mkdirSync(dir, { recursive: true });
  const table = new Map();

  for (const [i, caption] of lines.entries()) {
    const text = spoken(caption);
    if (!text) continue;
    const file = join(dir, `line-${String(i).padStart(3, '0')}.aiff`);
    execFileSync('say', ['-v', voice, ...(rate ? ['-r', String(rate)] : []), '-o', file, text]);
    const probe = execFileSync('ffprobe',
      ['-v', 'error', '-show_entries', 'format=duration', '-of', 'default=nw=1:nk=1', file],
      { encoding: 'utf8' });
    const ms = Math.round(Number(probe.trim()) * 1000);
    if (!Number.isFinite(ms)) throw new Error(`could not measure ${file}`);
    table.set(caption, { file, ms });
  }
  return table;
}

/**
 * Which lines get spoken, and when.
 *
 * A line still talking when the next beat arrives is dropped rather than mixed
 * over it: the track is a concat, not a mixer. Both the audio and the subtitles
 * are built from this one list, because deciding it twice is how you get a
 * subtitle for a line nobody says — one sat on screen over its predecessor for
 * four seconds in the first narrated cut of the reel.
 */
export function schedule(beats, table, frames) {
  if (!frames.length) return [];
  const t0 = frames[0].t;
  const cues = [];
  let cursor = 0;
  for (const b of beats) {
    const clip = table.get(b.text);
    if (!clip || b.at == null) continue;
    const at = Math.max(0, Math.round((b.at - t0) * 1000));
    if (at < cursor) continue;              // would talk over the line before it
    cues.push({ text: b.text, at, ms: clip.ms, file: clip.file });
    cursor = at + clip.ms;
  }
  return cues;
}

/**
 * The narration track: silence up to each line, then the line.
 *
 * Exact without a mixer, because schedule() has already refused the overlaps.
 */
export function narrationPlan(cues, frames) {
  if (!frames.length) return [];
  const t0 = frames[0].t;
  const plan = [];
  let cursor = 0;
  for (const c of cues) {
    plan.push({ silence: c.at - cursor, file: c.file, ms: c.ms });
    cursor = c.at + c.ms;
  }
  const total = Math.round((frames.at(-1).t - t0) * 1000);
  if (total > cursor) plan.push({ silence: total - cursor, file: null, ms: 0 });
  return plan;
}

/** Subtitles, because a recording with a voice is still watched muted. */
export function srt(cues) {
  const stamp = (ms) => {
    const h = String(Math.floor(ms / 3600000)).padStart(2, '0');
    const m = String(Math.floor(ms / 60000) % 60).padStart(2, '0');
    const sec = String(Math.floor(ms / 1000) % 60).padStart(2, '0');
    return `${h}:${m}:${sec},${String(ms % 1000).padStart(3, '0')}`;
  };
  return cues.map((c, i) => {
    const next = cues[i + 1];
    // A caption may hang on past its line, but never into the next one's: two
    // at once is unreadable, and the player is entitled to assume they queue.
    const cap = next ? next.at - 40 : Infinity;
    const end = Math.min(Math.max(c.at + c.ms + 400, c.at + 900), cap);
    // The real spelling, not the one the synthesiser was fed: "Seefoss" is for
    // the voice, and a subtitle that says it is a subtitle with a typo in it.
    return `${i + 1}\n${stamp(c.at)} --> ${stamp(end)}\n${stripped(c.text)}\n`;
  }).join('\n');
}
