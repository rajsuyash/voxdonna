import test from 'node:test';
import assert from 'node:assert/strict';
import { renderPlanPdf } from '../pdf.mjs';
import { loadCatalogue, fallbackPlan } from '../plan.mjs';

const catalogue = loadCatalogue();
const pages = (buf) => (buf.toString('latin1').match(/\/Type \/Page\b(?!s)/g) ?? []).length;
const lead = { name: 'Asha Rao', email: 'a@b.co', company: 'Rao Jewels', industry: 'jewellery', problem: 'We miss calls after 7pm and enquiries go cold.' };

test('PDF: %PDF header, exactly 2 pages, under 150 KB', async () => {
  const buf = await renderPlanPdf({ lead, plan: fallbackPlan(lead, catalogue), catalogue });
  assert.equal(buf.subarray(0, 4).toString(), '%PDF');
  assert.equal(pages(buf), 2);
  assert.ok(buf.length < 150 * 1024, `size ${buf.length}`);
});

test('PDF: very long problem, long company and a non-Latin name do not crash or add pages', async () => {
  const l = { ...lead, name: 'राहुल शर्मा', company: 'Ünïcödé 株式会社 '.repeat(8), problem: 'calls miss ho jaate hain after 7pm. '.repeat(80) };
  const buf = await renderPlanPdf({ lead: l, plan: fallbackPlan(l, catalogue), catalogue });
  assert.equal(pages(buf), 2);
  assert.ok(buf.length < 150 * 1024);
});

test('PDF: maximum-length model text still fits on 2 pages', async () => {
  const base = fallbackPlan(lead, catalogue);
  const plan = {
    summary: 'word '.repeat(59).trim(),
    next_step: 'word '.repeat(59).trim(),
    picks: base.picks.map((p) => ({ ...p, why: 'word '.repeat(47).trim(), first_step: 'word '.repeat(49).trim() })),
  };
  const l = { ...lead, problem: 'word '.repeat(200) };
  const buf = await renderPlanPdf({ lead: l, plan, catalogue });
  assert.equal(pages(buf), 2);
  assert.ok(buf.length < 150 * 1024);
});
