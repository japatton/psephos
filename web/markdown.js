/**
 * The small amount of Markdown a hunt transcript actually needs.
 *
 * Written rather than pulled in because the project has no dependencies, but
 * mostly because the threat model here is unusual and a general-purpose
 * renderer solves a different problem. The text arriving in a bubble is model
 * output and analyst pastes, and those pastes are adversary-influenced: a log
 * line, a command line, a filename someone else chose. So:
 *
 *   1. The input is escaped ONCE, up front, before any rule looks at it.
 *      Every transformation below operates on already-safe text, which means
 *      no rule can be tricked into emitting markup — the angle brackets are
 *      gone before the parser starts.
 *   2. Code spans and fences are lifted out before anything else runs and put
 *      back at the very end, so a log line inside a fence is never reformatted.
 *   3. Link targets are scheme-checked. `[click](javascript:...)` is the one
 *      construct in Markdown that turns text into execution, and an allowlist
 *      is the only reliable answer.
 *
 * Single-character emphasis is deliberately NOT supported. A hunt transcript
 * is full of `C:\Users\*` and `svc_backup_prod` and `*.dll`, and turning those
 * into italics silently corrupts the one thing an analyst is reading them for.
 * `**bold**` survives because a doubled asterisk is vanishingly rare in log
 * output and the model uses it constantly.
 */

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, c => ESCAPES[c]);

/** http, https and mailto only. Everything else renders as plain text. */
function safeHref(raw) {
  const url = String(raw ?? '').trim();
  // A leading control character or whitespace can hide the scheme from a
  // naive check while the browser still honours it.
  if (/[\u0000-\u0020]/.test(url)) return null;
  if (/^(https?:|mailto:)/i.test(url)) return url;
  // Protocol-relative and rooted paths are fine; they cannot carry a scheme.
  if (/^(\/|#)/.test(url)) return url;
  return null;
}

const inline = (text) => text
  // Bold first, so the inner text of a bold link still resolves.
  .replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, '<strong>$1</strong>')
  .replace(/\[([^\]\n]*)\]\(([^)\s]+)\)/g, (whole, label, href) => {
    const safe = safeHref(href);
    // Not a link we will follow: show what was written, do not invent markup.
    return safe
      ? `<a href="${safe}" target="_blank" rel="noopener noreferrer">${label || safe}</a>`
      : whole;
  });

/** A pipe table, but only when the header underline is actually there. */
function tableFrom(lines, start) {
  const head = lines[start];
  const rule = lines[start + 1];
  if (!head?.includes('|') || !/^\s*\|?[\s:|-]+\|[\s:|-]*$/.test(rule ?? '')) return null;
  if (!/-/.test(rule)) return null;

  const cells = (row) => row.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map(c => c.trim());
  const header = cells(head);
  const body = [];
  let i = start + 2;
  for (; i < lines.length && lines[i].includes('|') && lines[i].trim(); i++) body.push(cells(lines[i]));

  const th = header.map(c => `<th>${inline(c)}</th>`).join('');
  const tr = body.map(r => `<tr>${r.map(c => `<td>${inline(c)}</td>`).join('')}</tr>`).join('');
  return { html: `<table class="md-table"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`, next: i };
}

/**
 * @param {string} src raw text, NOT pre-escaped
 * @returns {string} HTML safe to assign to innerHTML
 */
export function renderMarkdown(src) {
  const escaped = escapeHtml(src);

  /*
    A sentinel the input cannot contain. It is built from characters that
    escaping has already removed from the text, so no paste can forge one and
    smuggle its own HTML back in through the restore step.
  */
  const KEY = `\u0001md${Math.random().toString(36).slice(2, 10)}\u0001`;
  const vault = [];
  const stash = (html) => `${KEY}${vault.push(html) - 1}${KEY}`;

  let text = escaped
    // Fenced blocks, with an optional language tag we keep only as a class.
    .replace(/```([\w+-]*)\n?([\s\S]*?)```/g, (_m, lang, body) => stash(
      `<pre class="md-pre"${lang ? ` data-lang="${lang}"` : ''}><code>${
        body.replace(/\n$/, '')}</code></pre>`))
    // Inline code. Runs after fences so a fence's backticks are already gone.
    .replace(/`([^`\n]+)`/g, (_m, code) => stash(`<code class="md-code">${code}</code>`));

  const lines = text.split('\n');
  const out = [];
  let para = [];
  let list = null;   // 'ul' | 'ol'
  let item = null;   // lines of the open <li>, or null when none is open

  const flushPara = () => {
    if (para.length) out.push(`<p>${inline(para.join(' '))}</p>`);
    para = [];
  };
  /*
    Held open rather than emitted on sight, so a wrapped line can still join
    it. See the continuation rule below for why that matters.
  */
  const flushItem = () => {
    if (item) out.push(`<li>${inline(item.join(' '))}</li>`);
    item = null;
  };
  const closeList = () => { flushItem(); if (list) { out.push(`</${list}>`); list = null; } };
  const breakBlock = () => { flushPara(); closeList(); };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.trim()) { breakBlock(); continue; }

    // A stashed fence occupies its own line and is already finished HTML.
    if (line.startsWith(KEY) && line.endsWith(KEY) && !line.slice(KEY.length, -KEY.length).includes(KEY)) {
      breakBlock();
      out.push(line);
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      breakBlock();
      const level = Math.min(6, heading[1].length + 2);   // h1 in a bubble would shout
      out.push(`<h${level} class="md-h">${inline(heading[2])}</h${level}>`);
      continue;
    }

    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { breakBlock(); out.push('<hr class="md-hr">'); continue; }

    // &gt; not > — escaping runs first, so the block rules see escaped text.
    const quote = /^&gt;\s?(.*)$/.exec(line);
    if (quote) {
      breakBlock();
      out.push(`<blockquote class="md-quote">${inline(quote[1])}</blockquote>`);
      continue;
    }

    const table = tableFrom(lines, i);
    if (table) { breakBlock(); out.push(table.html); i = table.next - 1; continue; }

    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const number = /^\s*\d{1,3}[.)]\s+(.*)$/.exec(line);
    if (bullet || number) {
      const want = bullet ? 'ul' : 'ol';
      flushPara();
      if (list !== want) { closeList(); out.push(`<${want} class="md-list">`); list = want; }
      else flushItem();
      item = [(bullet ?? number)[1]];
      continue;
    }

    /*
      Lazy continuation: an unmarked line under an open item belongs to that
      item. Everything that starts a block of its own — heading, quote, rule,
      fence, table, another bullet — has already been tested and returned
      above, so what reaches here is prose.

      Model output hard-wraps at column eighty. Without this rule the second
      line of every wrapped bullet closed the list and rendered as an
      unindented paragraph, which put half the sentences in a transcript
      outside the list they belonged to.
    */
    // Trimmed, because the indent under a bullet is list syntax rather than
    // content. HTML would collapse it anyway; this keeps the markup readable.
    if (item) { item.push(line.trim()); continue; }

    closeList();
    para.push(line);
  }
  breakBlock();

  let html = out.join('\n');
  // Restore innermost-last so a code span inside a fence comes back intact.
  for (let i = vault.length - 1; i >= 0; i--) {
    html = html.split(`${KEY}${i}${KEY}`).join(vault[i]);
  }
  return html;
}
