import test from 'node:test';
import assert from 'node:assert/strict';
import { validateField } from '../tools.mjs';

const PLACEHOLDERS = ['N/A', 'n/a', 'na', 'None', 'null', 'Unknown', 'not provided', 'Not Given', 'TBD', '-', '?', '', '  ', 'visitor', 'User', 'ANONYMOUS', ' "N/A". ', '(unknown)', 'none!'];

for (const field of ['name', 'company']) {
  test(`${field}: placeholders are rejected`, () => {
    for (const v of PLACEHOLDERS) {
      const r = validateField(field, v);
      assert.equal(r.ok, false, `${JSON.stringify(v)} should be rejected`);
    }
    assert.match(validateField(field, 'N/A').error, /placeholder/);
  });
}

test('real values containing placeholder words are accepted', () => {
  assert.deepEqual(validateField('name', 'Na Li'), { ok: true, value: 'Na Li' });
  assert.deepEqual(validateField('company', 'Unknown Pleasures Ltd'), { ok: true, value: 'Unknown Pleasures Ltd' });
  assert.equal(validateField('name', 'Nirav Mehta').ok, true);
});
