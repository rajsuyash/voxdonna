import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { PLANNER_INDUSTRIES, TOOL_DECLARATIONS, createLead, handleToolCall, plannerUrl, volumeBucket } from '../tools.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const assetsFile = join(here, '..', '..', 'assets', 'automation-plan', 'industries.json');
const appJs = readFileSync(join(here, '..', '..', 'assets', 'automation-plan', 'app.js'), 'utf8');

test('planner-industries.json matches assets/automation-plan/industries.json (ids and names, same order)', () => {
  const live = JSON.parse(readFileSync(assetsFile, 'utf8')).industries.map((i) => ({ id: i.id, name: i.name }));
  assert.equal(live.length, 44);
  assert.deepEqual(PLANNER_INDUSTRIES, live);
});

test('finish_intake declares industry_id as an enum of exactly those ids, names in the description', () => {
  const props = TOOL_DECLARATIONS.find((d) => d.name === 'finish_intake').parameters.properties;
  assert.equal(props.industry_id.type, 'STRING');
  assert.deepEqual(props.industry_id.enum, PLANNER_INDUSTRIES.map((i) => i.id));
  for (const i of PLANNER_INDUSTRIES) assert.ok(props.industry_id.description.includes(`${i.id}=${i.name}`), i.id);
  assert.ok(!TOOL_DECLARATIONS.find((d) => d.name === 'finish_intake').parameters.required.includes('industry_id'));
});

test('volumeBucket edges and unparseable text', () => {
  const cases = [['99', 'under-100'], ['100', '100-500'], ['499', '100-500'], ['500', '500-2000'], ['1999', '500-2000'],
    ['2000', '2000-plus'], ['1,200 calls a month', '500-2000'], ['2k', '2000-plus'], ['5 lakh', '2000-plus'],
    ['about two thousand', null], ['', null], [undefined, null]];
  for (const [input, want] of cases) assert.equal(volumeBucket(input), want, String(input));
});

test('bucket ids are exactly the ones app.js knows', () => {
  const ids = [...appJs.matchAll(/\{ id: '(under-100|100-500|500-2000|2000-plus)', label/g)].map((m) => m[1]);
  assert.deepEqual(ids, ['under-100', '100-500', '500-2000', '2000-plus']);
  for (const v of ['50', '200', '1000', '9000']) assert.ok(ids.includes(volumeBucket(v)));
});

test('plannerUrl builds the deep link and drops what it cannot trust', () => {
  const base = 'https://voxdonna.com/automation-plan.html';
  assert.equal(plannerUrl('jewellery-retail', '500'), `${base}?industry=jewellery-retail&volume=500-2000`);
  assert.equal(plannerUrl('jewellery-retail', 'lots'), `${base}?industry=jewellery-retail`);
  assert.equal(plannerUrl('nope', '50'), `${base}?volume=under-100`);
  assert.equal(plannerUrl(undefined, undefined), base);
  assert.equal(plannerUrl('real-estate&evil=1', '50'), `${base}?volume=under-100`);
});

test('handleToolCall: plan never asks the caller to ship a lead', () => {
  const lead = createLead();
  for (const [f, v] of [['name', 'A'], ['email', 'a@b.co'], ['problem', 'P']]) lead.set(f, v);
  const r = handleToolCall(lead, { name: 'finish_intake', args: { next: ['plan'], industry_id: 'real-estate' } });
  assert.equal('submit' in r, false);
  assert.deepEqual(r.events.map((e) => e.type), ['intake_complete', 'navigate']);
});
