import { fileURLToPath } from 'node:url';
import PDFDocument from 'pdfkit';

const FONT_REGULAR = fileURLToPath(new URL('./fonts/Inter-Regular.ttf', import.meta.url));
const FONT_BOLD = fileURLToPath(new URL('./fonts/Inter-SemiBold.ttf', import.meta.url));

const C = { bg: '#0a0a0c', copper: '#c17f59', copperLight: '#d4a574', text: '#f5f5f7', muted: '#a1a1a8', panel: '#16161a' };
const PAGE = { w: 595.28, h: 841.89, m: 48 };
const W = PAGE.w - PAGE.m * 2;
const CONTACT_URL = 'https://voxdonna.com/#contact';
const MAX_PROBLEM = 320;

const cut = (s, n) => (s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s);

export function renderPlanPdf({ lead, plan, catalogue: _catalogue, now = new Date() }) {
  return new Promise((resolve, reject) => {
    // bottom margin 0: text never auto-paginates, so the document is exactly the two pages drawn below.
    const doc = new PDFDocument({
      size: 'A4', margins: { top: PAGE.m, left: PAGE.m, right: PAGE.m, bottom: 0 }, autoFirstPage: false,
      info: { Title: 'Your automation plan', Author: 'VoxDonna', Creator: 'VoxDonna' },
    });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.registerFont('Inter', FONT_REGULAR);
    doc.registerFont('InterB', FONT_BOLD);

    // A glyph the font lacks (e.g. Devanagari) would render as a box; swap it for "?" instead.
    const hasGlyph = (ch) => { doc.font('Inter'); return doc._font.font.hasGlyphForCodePoint(ch.codePointAt(0)); };
    const safe = (s, fallback = '') => {
      const text = String(s ?? '').replace(/\s+/g, ' ').trim();
      const out = [...text].map((ch) => (/\s/.test(ch) || hasGlyph(ch) ? ch : '?')).join('');
      const letters = out.replace(/[\s?.,'\-]/g, '');
      return text && letters.length === 0 ? fallback : out;
    };

    const newPage = () => {
      doc.addPage();
      doc.rect(0, 0, PAGE.w, PAGE.h).fill(C.bg);
      doc.rect(0, 0, PAGE.w, 4).fill(C.copper);
      doc.font('InterB').fontSize(11).fillColor(C.copper).text('VoxDonna', PAGE.m, 34, { characterSpacing: 1.5 });
    };
    const footer = () => {
      doc.font('Inter').fontSize(9).fillColor(C.muted)
        .text('hello@voxdonna.com  ·  voxdonna.com', PAGE.m, PAGE.h - 40, { width: W, lineBreak: false });
    };
    const label = (text, y) => doc.font('InterB').fontSize(8.5).fillColor(C.copper)
      .text(text.toUpperCase(), PAGE.m, y, { width: W, characterSpacing: 1.4 });

    const name = cut(safe(lead.name, 'you'), 30);
    const company = cut(safe(lead.company), 45);
    const date = now.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

    // ---- Page 1
    newPage();
    doc.font('InterB').fontSize(30).fillColor(C.text).text('Your automation plan', PAGE.m, 78, { width: W });
    doc.font('Inter').fontSize(11).fillColor(C.muted)
      .text(`Prepared for ${[name, company].filter(Boolean).join(', ')}  ·  ${date}`, PAGE.m, 122, { width: W, height: 14, ellipsis: true });
    doc.moveTo(PAGE.m, 148).lineTo(PAGE.m + 56, 148).lineWidth(2).strokeColor(C.copper).stroke();

    label('What you told Donna', 166);
    const problem = `“${cut(safe(lead.problem), MAX_PROBLEM)}”`;
    doc.font('Inter').fontSize(11).fillColor(C.text);
    const ph = doc.heightOfString(problem, { width: W - 20, lineGap: 3 });
    doc.rect(PAGE.m, 184, 3, ph).fill(C.copper);
    doc.fillColor(C.text).text(problem, PAGE.m + 16, 184, { width: W - 20, lineGap: 3 });

    let y = 184 + ph + 22;
    doc.font('Inter').fontSize(11).fillColor(C.copperLight)
      .text(safe(plan.summary), PAGE.m, y, { width: W, lineGap: 3 });
    y += doc.heightOfString(safe(plan.summary), { width: W, lineGap: 3 }) + 22;

    label('Where to start, in order', y);
    y += 20;
    plan.picks.forEach((p, i) => {
      const why = safe(p.why);
      const titleH = 18;
      const whyH = doc.font('Inter').fontSize(10.5).heightOfString(why, { width: W - 58, lineGap: 2 });
      const h = 14 + titleH + whyH + 30;
      doc.roundedRect(PAGE.m, y, W, h, 8).fill(C.panel);
      doc.font('InterB').fontSize(22).fillColor(C.copper).text(String(i + 1), PAGE.m + 14, y + 12, { width: 24, lineBreak: false });
      doc.font('InterB').fontSize(13).fillColor(C.text).text(safe(p.title), PAGE.m + 44, y + 14, { width: W - 58, lineBreak: false });
      doc.font('Inter').fontSize(10.5).fillColor(C.muted).text(why, PAGE.m + 44, y + 14 + titleH, { width: W - 58, lineGap: 2 });
      const fy = y + 14 + titleH + whyH + 8;
      doc.font('InterB').fontSize(9).fillColor(C.copperLight)
        .text(`Effort: ${safe(p.effort)}`, PAGE.m + 44, fy, { width: 150, lineBreak: false });
      doc.font('Inter').fontSize(9).fillColor(C.copperLight)
        .text('See how it works', PAGE.m + 200, fy, { width: 150, lineBreak: false, link: p.url, underline: true });
      y += h + 10;
    });
    footer();

    // ---- Page 2
    newPage();
    doc.font('InterB').fontSize(26).fillColor(C.text).text('Your first move', PAGE.m, 78, { width: W });
    doc.moveTo(PAGE.m, 116).lineTo(PAGE.m + 56, 116).lineWidth(2).strokeColor(C.copper).stroke();

    const first = plan.picks[0];
    doc.font('InterB').fontSize(13).fillColor(C.copperLight).text(safe(first.title), PAGE.m, 136, { width: W });
    const step = safe(first.first_step);
    doc.font('Inter').fontSize(14).fillColor(C.text);
    const sh = doc.heightOfString(step, { width: W - 40, lineGap: 4 });
    doc.roundedRect(PAGE.m, 164, W, sh + 36, 8).fill(C.panel);
    doc.font('Inter').fontSize(14).fillColor(C.text).text(step, PAGE.m + 20, 182, { width: W - 40, lineGap: 4 });
    let y2 = 164 + sh + 36 + 30;

    label('Then, in order', y2);
    y2 += 20;
    plan.picks.slice(1).forEach((p, i) => {
      const line = `${i + 2}.  ${safe(p.title)}`;
      doc.font('InterB').fontSize(11.5).fillColor(C.text).text(line, PAGE.m, y2, { width: W });
      y2 += doc.heightOfString(line, { width: W }) + 4;
      const s = safe(p.first_step);
      doc.font('Inter').fontSize(10.5).fillColor(C.muted).text(s, PAGE.m + 20, y2, { width: W - 20, lineGap: 2 });
      y2 += doc.heightOfString(s, { width: W - 20, lineGap: 2 }) + 16;
    });

    y2 += 8;
    label('Next', y2);
    y2 += 20;
    const next = safe(plan.next_step);
    doc.font('Inter').fontSize(12).fillColor(C.text).text(next, PAGE.m, y2, { width: W, lineGap: 3 });
    y2 += doc.heightOfString(next, { width: W, lineGap: 3 }) + 24;

    doc.roundedRect(PAGE.m, y2, 200, 40, 20).fill(C.copper);
    doc.font('InterB').fontSize(12).fillColor(C.bg).text('Book a call', PAGE.m, y2 + 13, { width: 200, align: 'center', lineBreak: false });
    doc.link(PAGE.m, y2, 200, 40, CONTACT_URL);
    doc.font('Inter').fontSize(9.5).fillColor(C.muted).text('voxdonna.com/#contact', PAGE.m + 216, y2 + 15, { lineBreak: false, link: CONTACT_URL, underline: true });
    footer();

    doc.end();
  });
}
