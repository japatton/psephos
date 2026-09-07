import { newId } from '../lib/ids.js';
import { missionPaths, readJson } from './mission.js';
import { existsSync } from 'node:fs';

/**
 * Activity threads: the separate operators an engagement is tracking.
 *
 * Mission data, not source. Separate threads exist because MITRE cell
 * assignments can confirm more than one operator, and collapsing them loses
 * that — but which threads, what they are called and who is assessed to be
 * behind them are facts about one engagement. They lived here as a const with
 * one exercise's threads and one team's names in them, which meant every new
 * mission started by inheriting somebody else's actors.
 *
 * A profile with no threads.json gets none. That is the honest starting state:
 * threads are what the hunt discovers, not what it is issued with.
 */
function seedFor() {
  let path;
  try { path = missionPaths().threads; } catch { return []; }
  if (!path || !existsSync(path)) return [];
  try {
    const { threads } = readJson(path);
    return Array.isArray(threads) ? threads : [];
  } catch {
    return [];
  }
}

/** Idempotent, so a restart never disturbs a thread an analyst has edited. */
export function seedThreads(db, threads = seedFor()) {
  const ins = db.prepare(`insert or ignore into threads
    (id, key, name, assessed_cell, status, color) values (?,?,?,?,?,?)`);
  for (const t of threads) {
    ins.run(newId(), t.key, t.name, t.assessedCell ?? t.assessed_cell ?? '',
      t.status ?? '', t.color ?? '#8899ad');
  }
  return threads.length;
}

export function listThreads(db) {
  return db.prepare('select * from threads order by key').all();
}

/*
  Picking a colour for a thread.

  A thread's colour is not decoration: on the Timeline it is the fill and stroke
  of every mark, so it is doing the same job there that the verdict colour does
  on the Network Map. Five hues are already spoken for and a thread must not
  borrow one, or a mark in one view reads as a meaning it carries in another:

    red / amber / green   verdicts, on the map and in the state column
    cyan / magenta        the brand, and deliberately absent from data
    purple                confirmed causality, on the timeline arcs

  That leaves blue and the neutrals, which is not much. It is enough for the
  handful of threads an engagement actually runs, and the shortage is the point:
  a sixth arbitrary hue would be indistinguishable from something that means
  something.
*/
