import { test } from 'node:test';
import assert from 'node:assert';
import { renderMarkdown as md } from '../web/markdown.js';

/*
  The text this renders is model output and analyst pastes, and the pastes are
  adversary-influenced: a log line, a command line, a filename someone else
  chose. Escaping happens once up front so no rule below can be tricked into
  emitting markup — these tests are mostly about proving that holds.
*/

// --- the part that matters -------------------------------------------------------

test('a script tag in pasted text is inert', () => {
  const out = md('log line: <script>alert(1)</script> end');
  assert.equal(out.includes('<script'), false);
  assert.match(out, /&lt;script&gt;/);
});

test('an image with an error handler cannot be smuggled in', () => {
  const out = md('<img src=x onerror=alert(1)>');
  assert.equal(out.includes('<img'), false);
  assert.equal(out.includes('onerror'), true, 'shown as text');
  assert.equal(/<[a-z]+[^>]*onerror/i.test(out), false, 'but never as an attribute');
});

test('a javascript: link renders as text, not a link', () => {
  const out = md('[click me](javascript:alert(1))');
  assert.equal(out.includes('<a '), false);
  assert.match(out, /\[click me\]/, 'the source is shown verbatim instead');
});

test('data: and vbscript: targets are refused too', () => {
  for (const scheme of ['data:text/html;base64,PHN2Zz4=', 'vbscript:msgbox', 'VBScript:x', 'JaVaScRiPt:x']) {
    assert.equal(md(`[x](${scheme})`).includes('<a '), false, scheme);
  }
});

test('a scheme hidden behind a control character is refused', () => {
  // The browser tolerates these; a naive prefix check does not see them.
  assert.equal(md('[x](java\tscript:alert(1))').includes('<a '), false);
  assert.equal(md('[x]( javascript:alert(1))').includes('<a '), false);
});

test('http, https and mailto links are allowed, and cannot break out', () => {
  assert.match(md('[docs](https://example.test/a?b=1)'),
    /<a href="https:\/\/example\.test\/a\?b=1" target="_blank" rel="noopener noreferrer">docs<\/a>/);
  assert.match(md('[mail](mailto:a@example.test)'), /<a href="mailto:a@example\.test"/);

  // A quote in the target would end the attribute if it were not already escaped.
  const out = md('[x](https://example.test/" onmouseover="alert(1))');
  assert.equal(/onmouseover="alert/.test(out), false);
});

test('a link label cannot inject markup', () => {
  const out = md('[<b>bold</b>](https://example.test)');
  assert.equal(out.includes('<b>'), false);
  assert.match(out, /&lt;b&gt;/);
});

/*
  The sentinel that holds code blocks aside is built from characters escaping
  has already removed, so a paste cannot forge one and have its own HTML
  restored in the final step.
*/
test('text imitating the internal placeholder is not restored as HTML', () => {
  const out = md('\u0001md0\u0001 and \u0001mdabcdefgh\u00010\u0001mdabcdefgh\u0001');
  assert.equal(out.includes('<pre'), false);
  assert.equal(out.includes('<code'), false);
});

// --- code, which is most of what a transcript carries -----------------------------

test('a fenced block is preserved verbatim', () => {
  const out = md('before\n```\nrm -rf /tmp/*\ncat /etc/passwd\n```\nafter');
  assert.match(out, /<pre class="md-pre"><code>rm -rf \/tmp\/\*\ncat \/etc\/passwd<\/code><\/pre>/);
});

test('a language tag becomes an attribute, not markup', () => {
  assert.match(md('```bash\nls\n```'), /<pre class="md-pre" data-lang="bash">/);
  assert.equal(md('```"><script>x</script>\nls\n```').includes('<script'), false);
});

test('markdown inside a fence is left alone', () => {
  const out = md('```\n**not bold** and [not a link](https://example.test)\n```');
  assert.equal(out.includes('<strong>'), false);
  assert.equal(out.includes('<a '), false);
});

test('inline code is preserved and not reformatted', () => {
  const out = md('run `net user /add **evil**` now');
  assert.match(out, /<code class="md-code">net user \/add \*\*evil\*\*<\/code>/);
});

test('an unclosed fence does not swallow the rest silently', () => {
  const out = md('text\n```\nstill going');
  assert.ok(out.includes('still going'), 'content survives even if the fence never closes');
});

// --- the fidelity rule ------------------------------------------------------------

/*
  A hunt transcript is full of paths, wildcards and service accounts. Turning
  those into italics corrupts the one thing an analyst is reading them for, so
  single-character emphasis is not supported at all.
*/
test('paths and wildcards are never italicised', () => {
  for (const s of ['C:\\Users\\*\\AppData', 'svc_backup_prod ran', '*.dll loaded', 'a_b_c_d']) {
    const out = md(s);
    assert.equal(out.includes('<em>'), false, s);
    assert.equal(out.includes('<i>'), false, s);
  }
});

test('backslash paths and UNC shares survive verbatim', () => {
  // Half the evidence in this tool is Windows paths. A renderer that eats a
  // backslash changes what the analyst is reading.
  const path = String.raw`C:\Users\svc_backup\AppData\Local\Temp`;
  const unc = String.raw`\\FILESRV-01\share$`;
  assert.ok(md(path).includes(path), md(path));
  assert.ok(md(unc).includes(unc), md(unc));
});

test('bold still works, because the model uses it constantly', () => {
  assert.match(md('this is **important** here'), /this is <strong>important<\/strong> here/);
  assert.equal(md('2 ** 8 = 256').includes('<strong>'), false, 'spaced asterisks are arithmetic');
});

// --- ordinary structure -----------------------------------------------------------

test('headings render, but never as h1 inside a bubble', () => {
  assert.match(md('# Top'), /<h3 class="md-h">Top<\/h3>/);
  assert.match(md('### Third'), /<h5 class="md-h">Third<\/h5>/);
});

test('bullet and numbered lists render as lists', () => {
  assert.match(md('- one\n- two'), /<ul class="md-list">\n<li>one<\/li>\n<li>two<\/li>\n<\/ul>/);
  assert.match(md('1. one\n2. two'), /<ol class="md-list">/);
});

test('switching list type closes the first list', () => {
  const out = md('- a\n1. b');
  assert.match(out, /<\/ul>/);
  assert.match(out, /<ol class="md-list">/);
});

test('a table renders only when the header rule is present', () => {
  const out = md('| Host | Verdict |\n| --- | --- |\n| DC | confirmed |');
  assert.match(out, /<table class="md-table">/);
  assert.match(out, /<th>Host<\/th>/);
  assert.match(out, /<td>confirmed<\/td>/);

  // A log line full of pipes is not a table.
  assert.equal(md('a | b | c\nd | e | f').includes('<table'), false);
});

test('paragraphs, quotes and rules', () => {
  assert.match(md('one\ntwo\n\nthree'), /<p>one two<\/p>[\s\S]*<p>three<\/p>/);
  assert.match(md('> quoted'), /<blockquote class="md-quote">quoted<\/blockquote>/);
  assert.match(md('---'), /<hr class="md-hr">/);
});

test('empty and non-string input do not throw', () => {
  for (const v of ['', null, undefined, 0, {}]) {
    assert.doesNotThrow(() => md(v), String(v));
  }
});

test('plain text with no markdown comes through as a paragraph', () => {
  assert.match(md('just a sentence'), /<p>just a sentence<\/p>/);
});

/*
  What the model actually sends. Its prose is hard-wrapped, so nearly every
  bullet it writes arrives as two or three lines, and the renderer used to end
  the list at the first of them.
*/
test('a wrapped line stays inside the bullet it belongs to', () => {
  const html = md('- One host out of six carries the entry.\n  The other five ran the same build.\n- Named to read as maintenance.');
  assert.match(html, /<li>One host out of six carries the entry\. The other five ran the same build\.<\/li>/);
  assert.equal(html.match(/<ul/g).length, 1, 'one list, not two');
  assert.equal(html.includes('<p>'), false, 'no continuation escaped into a paragraph');
});

test('a blank line still ends the list', () => {
  const html = md('- item\n\nafter');
  assert.match(html, /<li>item<\/li>\n<\/ul>/);
  assert.match(html, /<p>after<\/p>/);
});

test('a block construct under an item ends the item rather than joining it', () => {
  for (const [after, pattern] of [
    ['# Heading', /<h3 class="md-h">Heading<\/h3>/],
    ['> quoted', /<blockquote/],
    ['---', /<hr class="md-hr">/],
  ]) {
    const html = md(`- item\n${after}`);
    assert.match(html, /<li>item<\/li>\n<\/ul>/, after);
    assert.match(html, pattern, after);
  }
});

test('an ordered list following a bulleted one is a separate list', () => {
  const html = md('- bullet\n1. numbered');
  assert.match(html, /<li>bullet<\/li>\n<\/ul>\n<ol class="md-list">\n<li>numbered<\/li>/);
});
