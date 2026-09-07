import { makeZip } from './zip.js';
import { COLUMNS, HEADERS } from '../store/records.js';

/**
 * Workbook export, shaped like the analyst's existing analyst workbook: a legend
 * sheet followed by one sheet per activity thread. Threads are kept apart
 * because the cell assignments confirm multiple operators, and collapsing them
 * into one sheet loses that distinction.
 *
 * Uses inline strings rather than a shared string table — slightly larger on
 * disk, considerably simpler, and Excel reads it identically.
 */

const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  // Control characters are illegal in XML 1.0 and Excel refuses the file.
  .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');

const colName = (i) => {
  let s = '';
  for (let n = i + 1; n > 0; n = Math.floor((n - 1) / 26)) {
    s = String.fromCharCode(65 + ((n - 1) % 26)) + s;
  }
  return s;
};

/** Excel rejects these characters in a sheet name, and caps it at 31 chars. */
const sheetName = (raw, taken) => {
  let name = String(raw).replace(/[[\]:*?/\\]/g, ' ').trim().slice(0, 31) || 'Sheet';
  let n = 2;
  while (taken.has(name.toLowerCase())) {
    const suffix = ` (${n++})`;
    name = name.slice(0, 31 - suffix.length) + suffix;
  }
  taken.add(name.toLowerCase());
  return name;
};

function sheetXml(rows) {
  const body = rows.map((cells, r) => {
    const tds = cells.map((v, c) => {
      if (v == null || v === '') return '';
      const style = r === 0 ? ' s="1"' : ' s="2"';
      return `<c r="${colName(c)}${r + 1}"${style} t="inlineStr"><is><t xml:space="preserve">${esc(v)}</t></is></c>`;
    }).join('');
    return `<row r="${r + 1}">${tds}</row>`;
  }).join('');

  const lastCol = colName(Math.max(0, HEADERS.length - 1));
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetPr><outlinePr summaryBelow="1"/></sheetPr>
<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="15"/>
<cols>
<col min="1" max="2" width="22" customWidth="1"/>
<col min="3" max="6" width="18" customWidth="1"/>
<col min="7" max="10" width="24" customWidth="1"/>
<col min="11" max="12" width="60" customWidth="1"/>
<col min="13" max="16" width="20" customWidth="1"/>
<col min="17" max="18" width="26" customWidth="1"/>
</cols>
<sheetData>${body}</sheetData>
<autoFilter ref="A1:${lastCol}${Math.max(1, rows.length)}"/>
</worksheet>`;
}

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
</fonts>
<fills count="3">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1F2933"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment vertical="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>`;

/**
 * @param {object[]} records
 * @param {object[]} threads
 * @param {{ generatedAt?: string }} [opts]
 * @returns {Buffer} .xlsx bytes
 */
export function recordsToXlsx(records, threads, { generatedAt = '' } = {}) {
  const taken = new Set();
  const sheets = [];

  // Legend first, mirroring the workbook the team already reads.
  const legend = [
    ['Psephos export'],
    [generatedAt ? `Generated ${generatedAt}` : ''],
    [''],
    ['Sheet', 'Key', 'Assessed cell', 'Status', 'Rows'],
  ];

  const groups = [
    ...threads.map(t => ({ key: t.key, label: t.name, cell: t.assessed_cell, status: t.status, id: t.id })),
    { key: '—', label: 'Unassigned', cell: '', status: '', id: null },
  ];

  for (const g of groups) {
    const rows = records.filter(r => (r.thread_id ?? null) === g.id);
    if (rows.length === 0 && g.id === null) continue;
    const name = sheetName(g.label, taken);
    legend.push([name, g.key, g.cell ?? '', g.status ?? '', String(rows.length)]);
    sheets.push({
      name,
      rows: [HEADERS, ...rows.map(r => COLUMNS.map(c => r[c]))],
    });
  }

  legend.push(['']);
  legend.push(['TOTAL', '', '', '', String(records.length)]);
  legend.push(['']);
  legend.push(['Exported from Psephos. Times are as recorded by the analyst; the timeline']);
  legend.push(['tiers each one as exact, approximate or unplaceable rather than discarding it.']);

  const all = [{ name: sheetName('README - Legend', taken), rows: legend }, ...sheets];

  const parts = [
    {
      name: '[Content_Types].xml',
      data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
${all.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('\n')}
</Types>`,
    },
    {
      name: '_rels/.rels',
      data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
    },
    {
      name: 'xl/workbook.xml',
      data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>${all.map((s, i) => `<sheet name="${esc(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets>
</workbook>`,
    },
    {
      name: 'xl/_rels/workbook.xml.rels',
      data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
${all.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('\n')}
<Relationship Id="rId${all.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`,
    },
    { name: 'xl/styles.xml', data: STYLES },
    ...all.map((s, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, data: sheetXml(s.rows) })),
  ];

  return makeZip(parts);
}
