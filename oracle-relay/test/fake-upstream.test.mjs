import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import { startFakeUpstream } from './fake-upstream.mjs';

const SETUP = { setup: { model: 'projects/p/locations/l/publishers/google/models/m', generationConfig: { responseModalities: ['AUDIO'] }, systemInstruction: { parts: [{ text: 'x' }] }, tools: [{ functionDeclarations: [{ name: 'save_field' }, { name: 'navigate' }, { name: 'finish_intake' }] }] } };

async function closeCode(messages) {
  const fake = await startFakeUpstream();
  const ws = new WebSocket(fake.url);
  await once(ws, 'open');
  for (const m of messages) ws.send(typeof m === 'string' ? m : JSON.stringify(m));
  const [code, reason] = await once(ws, 'close');
  await fake.close();
  return { code, reason: reason.toString(), violations: fake.violations };
}

test('fake upstream closes 1008 on anything unknown or malformed', async () => {
  for (const bad of [
    ['{not json'],
    [{ realtimeInput: { text: 'hi' } }], // before setup
    [SETUP, { nope: 1 }],
    [SETUP, { realtimeInput: { audio: { data: 'AA', mimeType: 'audio/wav' } } }],
    [SETUP, { realtimeInput: { text: 'a', audio: { data: 'AA', mimeType: 'audio/pcm;rate=16000' } } }],
    [SETUP, { toolResponse: { functionResponses: [{ id: 1 }] } }],
    [{ setup: { ...SETUP.setup, bogusField: 1 } }],
  ]) {
    const r = await closeCode(bad);
    assert.equal(r.code, 1008, JSON.stringify(bad).slice(0, 80));
    assert.equal(r.violations.length, 1);
    assert.ok(r.reason.length > 0);
  }
});

test('fake upstream accepts a valid setup', async () => {
  const fake = await startFakeUpstream();
  const ws = new WebSocket(fake.url);
  await once(ws, 'open');
  ws.send(JSON.stringify(SETUP));
  const [data] = await once(ws, 'message');
  assert.deepEqual(JSON.parse(data.toString()), { setupComplete: {} });
  ws.close();
  await fake.close();
});
