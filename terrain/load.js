import { readFileSync } from 'node:fs';
import { missionPaths } from '../store/mission.js';

const cache = new Map();

/**
 * The seeded estate, read from the active mission profile. Read-only at
 * runtime — the map grows through discovery (see store/hosts.js resolveHost),
 * not by editing this file in place.
 */
export function loadTerrain(path = missionPaths().terrain) {
  if (cache.has(path)) return cache.get(path);
  // Strip a leading BOM: anything saved by a Windows editor, or written by
  // PowerShell's Set-Content -Encoding UTF8, carries one and JSON.parse
  // rejects it with a message that does not mention the BOM at all.
  const terrain = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));

  if (!Array.isArray(terrain.enclaves) || terrain.enclaves.length === 0) {
    throw new Error(`terrain at ${path} has no enclaves`);
  }
  for (const e of terrain.enclaves) {
    if (!e.key || !Array.isArray(e.segments)) {
      throw new Error(`terrain enclave ${e.key ?? '(unnamed)'} is malformed`);
    }
  }
  cache.set(path, terrain);
  return terrain;
}

/** Flatten to a host list, carrying enclave and segment context down. */
export function terrainHosts(terrain = loadTerrain()) {
  return terrain.enclaves.flatMap(e =>
    e.segments.flatMap(s =>
      s.hosts.map(h => ({
        ...h,
        enclave: e.name || e.key,
        segment: s.name,
        cidr: s.cidr,
        // Written by the terrain survey. Absent from a hand-built file.
        presence: h.presence ?? 'unsurveyed',
        presenceNote: h.presenceNote ?? '',
        domainJoined: h.domainJoined ?? null,
        nameConflict: h.nameConflict ?? '',
        observedFrom: Array.isArray(h.observedFrom) ? h.observedFrom : [],
      }))));
}
