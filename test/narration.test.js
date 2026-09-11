import { test } from 'node:test';
import assert from 'node:assert';
import { spoken, stripped, schedule, narrationPlan, srt } from '../tools/narration.mjs';

/*
  The narration scheduler, which nothing covered.

  It earned a test the hard way: the audio dropped a line that would have
  talked over its predecessor, the subtitles did not, and the published reel
  carried a caption with no voice under it sitting on top of the caption
  before it for four seconds. Nobody watching a take notices a subtitle that
  is four seconds early — so the check has to be here.
*/

/** Beats as the recorder logs them: caption text, and the frame time it went up. */
const beat = (text, at) => ({ text, at });
const clips = (...pairs) =>
  new Map(pairs.map(([text, ms]) => [text, { file: `${text}.aiff`, ms }]));
/** Frame timestamps are seconds, and the first frame is t0 rather than zero. */
const frames = (from, to) => [{ t: from }, { t: to }];

const parse = (text) => text.trim().split('\n\n').map((block) => {
  const [, times, ...rest] = block.split('\n');
  const ms = (t) => {
    const [h, m, s] = t.split(':');
    const [sec, milli] = s.split(',');
    return (+h * 3600 + +m * 60 + +sec) * 1000 + +milli;
  };
  const [start, end] = times.split(' --> ').map(ms);
  return { start, end, text: rest.join('\n') };
});

// --- what gets spoken -------------------------------------------------------

test('a line that would talk over the one before it is dropped', () => {
  const cues = schedule(
    [beat('first', 100), beat('second', 102)],
    clips(['first', 5000], ['second', 2000]),
    frames(100, 120));
  assert.deepEqual(cues.map(c => c.text), ['first']);
});

test('a line that starts after the last one finishes is kept', () => {
  const cues = schedule(
    [beat('first', 100), beat('second', 106)],
    clips(['first', 5000], ['second', 2000]),
    frames(100, 120));
  assert.deepEqual(cues.map(c => c.text), ['first', 'second']);
  assert.deepEqual(cues.map(c => c.at), [0, 6000]);
});

test('a beat with no clip and a beat with no timestamp are both skipped', () => {
  const cues = schedule(
    [beat('silent card', 100), beat('no time', null), beat('spoken', 110)],
    clips(['no time', 1000], ['spoken', 1000]),
    frames(100, 120));
  assert.deepEqual(cues.map(c => c.text), ['spoken']);
});

// --- the subtitles agree with the voice -------------------------------------

test('no subtitle exists for a line the voice never says', () => {
  const beats = [beat('first', 100), beat('second', 102)];
  const table = clips(['first', 5000], ['second', 2000]);
  const cues = schedule(beats, table, frames(100, 120));
  const subs = parse(srt(cues));
  assert.equal(subs.length, 1);
  assert.equal(subs[0].text, 'first');
});

test('no two subtitles are ever on screen at once', () => {
  const cues = schedule(
    [beat('one', 100), beat('two', 101), beat('three', 103), beat('four', 103.2)],
    clips(['one', 900], ['two', 1800], ['three', 200], ['four', 900]),
    frames(100, 130));
  const subs = parse(srt(cues));
  assert.ok(subs.length > 1, 'needs at least two cues to be a real check');
  for (const [i, cue] of subs.slice(0, -1).entries()) {
    assert.ok(cue.end <= subs[i + 1].start,
      `cue ${i + 1} (${cue.text}) runs to ${cue.end}, past ${subs[i + 1].start}`);
  }
});

test('a subtitle always outlasts its own line', () => {
  const cues = schedule(
    [beat('one', 100), beat('two', 110)],
    clips(['one', 2000], ['two', 3000]),
    frames(100, 130));
  const subs = parse(srt(cues));
  assert.ok(subs[0].end >= subs[0].start + 2000);
  assert.ok(subs[1].end >= subs[1].start + 3000);
});

test('a subtitle is on screen long enough to read even for a clipped line', () => {
  const cues = schedule([beat('short', 100)], clips(['short', 120]), frames(100, 130));
  const subs = parse(srt(cues));
  assert.ok(subs[0].end - subs[0].start >= 900);
});

test('the subtitle keeps the real spelling the synthesiser was not given', () => {
  const line = 'Psephos reads the ATT&CK matrix.';
  assert.equal(spoken(line), 'Seefoss reads the attack matrix.');
  const cues = schedule([beat(line, 100)], clips([line, 2000]), frames(100, 110));
  assert.equal(parse(srt(cues))[0].text, line);
});

test('markup is cyan on screen, absent from the ear and from the subtitle', () => {
  assert.equal(stripped('<b>One of six</b> is the finding.'), 'One of six is the finding.');
  assert.equal(spoken('<b>One of six</b> is the finding.'), 'One of six is the finding.');
});

// --- the audio track lines up ----------------------------------------------

test('the track is silence and clips that sum to the recording', () => {
  const cues = schedule(
    [beat('one', 101), beat('two', 106)],
    clips(['one', 2000], ['two', 3000]),
    frames(100, 115));
  const plan = narrationPlan(cues, frames(100, 115));
  const total = plan.reduce((n, s) => n + s.silence + s.ms, 0);
  assert.equal(total, 15000);
  assert.deepEqual(plan.map(s => s.silence), [1000, 3000, 6000]);
});

test('no step of the track asks ffmpeg for a negative silence', () => {
  const cues = schedule(
    [beat('one', 100), beat('two', 102), beat('three', 104)],
    clips(['one', 1900], ['two', 1900], ['three', 500]),
    frames(100, 120));
  for (const step of narrationPlan(cues, frames(100, 120))) {
    assert.ok(step.silence >= 0, `negative silence: ${step.silence}`);
  }
});

test('a recording with no frames yields no schedule and no track', () => {
  assert.deepEqual(schedule([beat('one', 100)], clips(['one', 1000]), []), []);
  assert.deepEqual(narrationPlan([], []), []);
  assert.equal(srt([]), '');
});
