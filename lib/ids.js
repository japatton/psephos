import { randomUUID } from 'node:crypto';

/** Server-side identifier for every store row. Clients never supply one. */
export const newId = () => randomUUID();

/** Single source of "now" so timestamps are uniform across stores. */
export const nowIso = () => new Date().toISOString();
