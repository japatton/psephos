/**
 * What the turns cost, and who spent it.
 *
 * The prompt builder says outright that it is the analyst's quota being spent.
 * Nothing recorded how much: the runner surfaced Claude's own rate-limit
 * percentage as a warning when one arrived, which is useful in the moment and
 * gone afterwards. This is a team tool — four people on a roster spend one
 * shared quota — so when it runs low the question is where it went, and the
 * answer was being discarded.
 *
 * Only turns that reported usage are counted. A turn whose provider said
 * nothing has an unknown cost, and folding it in as zero would quietly drag
 * every average down.
 */

const SUMS = `
  count(*) as turns,
  coalesce(sum(input_tokens), 0)  as input_tokens,
  coalesce(sum(output_tokens), 0) as output_tokens,
  coalesce(sum(cost_usd), 0)      as cost_usd,
  coalesce(sum(duration_ms), 0)   as duration_ms`;

const MEASURED = "where input_tokens is not null or output_tokens is not null";

/** Per chat window. */
export const usageBySession = (db) => db.prepare(`
  select session_id, ${SUMS}
  from messages ${MEASURED}
  group by session_id
  order by cost_usd desc, input_tokens desc`).all();

/**
 * Per person. Joined through the session because that is who the window belongs
 * to — a message row has a role, not an owner.
 */
export const usageByMember = (db) => db.prepare(`
  select s.analyst as analyst,
    count(*) as turns,
    coalesce(sum(m.input_tokens), 0)  as input_tokens,
    coalesce(sum(m.output_tokens), 0) as output_tokens,
    coalesce(sum(m.cost_usd), 0)      as cost_usd,
    coalesce(sum(m.duration_ms), 0)   as duration_ms
  from messages m join sessions s on s.id = m.session_id
  where m.input_tokens is not null or m.output_tokens is not null
  group by s.analyst
  order by cost_usd desc`).all();

/** The whole engagement. coalesce so an untouched store reports zero, not null. */
export const usageTotal = (db) =>
  db.prepare(`select ${SUMS} from messages ${MEASURED}`).get();
