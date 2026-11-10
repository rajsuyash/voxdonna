import { readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { boot, sleepMs } from './helpers.mjs';

const CONTRACT_TYPES = new Set(['ready', 'state', 'audio', 'interrupted', 'caption', 'field', 'navigate', 'intake_complete', 'error', 'ended']);
const call = (id, name, args) => ({ toolCall: { functionCalls: [{ id, name, args }] } });
const toolResp = (id) => (m) => m.toolResponse?.functionResponses?.some((f) => f.id === id);
const respOf = (m, id) => m.toolResponse.functionResponses.find((f) => f.id === id).response;

async function start(opts) {
  const env = await boot(opts);
  const c = await env.open();
  return { env, c };
}

test('happy path: save_field x3 -> finish_intake -> intake_complete', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;

  await fake.waitFor((m) => m.realtimeInput?.text === 'Hello');
  fake.send({ toolCall: { functionCalls: [
    { id: 'a', name: 'save_field', args: { field: 'name', value: '  Asha Rao ' } },
    { id: 'b', name: 'save_field', args: { field: 'email', value: 'asha@acme.in' } },
    { id: 'c', name: 'save_field', args: { field: 'problem', value: 'We miss half our inbound calls.' } },
  ] } });
  await c.waitFor((m) => m.type === 'field' && m.field === 'problem');
  assert.deepEqual(c.msgs.filter((m) => m.type === 'field').map((m) => [m.field, m.value]), [
    ['name', 'Asha Rao'], ['email', 'asha@acme.in'], ['problem', 'We miss half our inbound calls.'],
  ]);
  const saved = await fake.waitFor(toolResp('a'));
  assert.deepEqual(saved.toolResponse.functionResponses.map((f) => f.response.ok), [true, true, true]);

  fake.send(call('d', 'finish_intake', { next: ['plan'] }));
  const done = await c.waitFor((m) => m.type === 'intake_complete');
  assert.deepEqual(done.lead, { name: 'Asha Rao', email: 'asha@acme.in', problem: 'We miss half our inbound calls.' });
  assert.deepEqual(done.next, ['plan']);
  assert.equal(respOf(await fake.waitFor(toolResp('d')), 'd').ok, true);

  assert.deepEqual(fake.violations, [], 'relay only sent messages the strict fake accepts');
  for (const m of c.msgs) assert.ok(CONTRACT_TYPES.has(m.type), `unexpected message to browser: ${m.type}`);
  assert.ok(!c.msgs.some((m) => m.toolCall || m.name), 'raw tool calls never reach the browser');
});

test('audio, captions, state and interruption pass through the contract', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;

  c.send({ type: 'audio', data: 'QUFB' });
  const up = await fake.waitFor((m) => m.realtimeInput?.audio);
  assert.deepEqual(up.realtimeInput.audio, { data: 'QUFB', mimeType: 'audio/pcm;rate=16000' });

  fake.send({ inputTranscription: { text: 'my calls drop' } }); // top-level form
  await c.waitFor((m) => m.type === 'caption' && m.who === 'user' && m.text === 'my calls drop' && !m.final);
  await c.waitFor((m) => m.type === 'state' && m.state === 'thinking');

  fake.send({ serverContent: { inputTranscription: { text: ' more' } } }); // nested form
  await c.waitFor((m) => m.type === 'caption' && m.who === 'user' && m.text === ' more');

  fake.send({ serverContent: { modelTurn: { parts: [{ inlineData: { data: 'Qk9C', mimeType: 'audio/pcm;rate=24000' } }] }, outputTranscription: { text: 'Go on.' } } });
  await c.waitFor((m) => m.type === 'audio' && m.data === 'Qk9C');
  await c.waitFor((m) => m.type === 'state' && m.state === 'speaking');
  await c.waitFor((m) => m.type === 'caption' && m.who === 'user' && m.final);
  await c.waitFor((m) => m.type === 'caption' && m.who === 'donna' && m.text === 'Go on.');

  fake.send({ serverContent: { interrupted: true } });
  await c.waitFor((m) => m.type === 'interrupted');

  fake.send({ serverContent: { turnComplete: true } });
  await c.waitFor((m) => m.type === 'caption' && m.who === 'donna' && m.final);
});

test('navigate: valid key emits a mapped url, invalid keys error to the model with no event', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;

  fake.send(call('n1', 'navigate', { route: 'pricing' }));
  const nav = await c.waitFor((m) => m.type === 'navigate');
  assert.deepEqual(nav, { type: 'navigate', route: 'pricing', url: '/ai-voice-agents.html#pricing' });
  assert.equal(respOf(await fake.waitFor(toolResp('n1')), 'n1').ok, true);

  for (const [id, route] of [['n2', 'https://evil.example'], ['n3', 'constructor'], ['n4', undefined]]) {
    fake.send(call(id, 'navigate', { route }));
    const r = respOf(await fake.waitFor(toolResp(id)), id);
    assert.equal(r.ok, false, `route ${route}`);
    assert.match(r.error, /unknown route/);
  }
  assert.equal(c.msgs.filter((m) => m.type === 'navigate').length, 1, 'only the valid key navigated');
});

test('finish_intake with missing fields returns the missing list and emits nothing', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;

  fake.send(call('s', 'save_field', { field: 'name', value: 'Asha' }));
  await c.waitFor((m) => m.type === 'field');
  fake.send(call('f', 'finish_intake', { next: ['plan'] }));
  const r = respOf(await fake.waitFor(toolResp('f')), 'f');
  assert.deepEqual(r, { ok: false, missing: ['email', 'problem'] });
  await c.expectNone((m) => m.type === 'intake_complete');
});

test('bad email is rejected from the model and from the visitor', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;

  fake.send(call('e', 'save_field', { field: 'email', value: 'asha at acme dot in' }));
  const r = respOf(await fake.waitFor(toolResp('e')), 'e');
  assert.equal(r.ok, false);
  assert.match(r.error, /email/);

  c.send({ type: 'field_edit', field: 'email', value: 'nope@' });
  const err = await c.waitFor((m) => m.type === 'error' && m.code === 'invalid_field');
  assert.match(err.message, /email/);
  await c.expectNone((m) => m.type === 'field');

  fake.send(call('x', 'save_field', { field: 'password', value: 'hunter2' }));
  assert.equal(respOf(await fake.waitFor(toolResp('x')), 'x').ok, false, 'unknown field refused');
  fake.send(call('y', 'save_field', { field: 'problem', value: 'x'.repeat(1501) }));
  assert.equal(respOf(await fake.waitFor(toolResp('y')), 'y').ok, false, 'problem over 1500 chars refused');
  fake.send(call('z', 'save_field', { field: 'company', value: 'x'.repeat(301) }));
  assert.equal(respOf(await fake.waitFor(toolResp('z')), 'z').ok, false, 'other fields over 300 chars refused');
  fake.send(call('w', 'rm_rf', {}));
  assert.equal(respOf(await fake.waitFor(toolResp('w')), 'w').ok, false, 'unknown tool refused');
});

test('valid field_edit updates lead state, echoes a field event and tells the model', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  c.send({ type: 'field_edit', field: 'email', value: ' fix@acme.in ' });
  const f = await c.waitFor((m) => m.type === 'field');
  assert.deepEqual(f, { type: 'field', field: 'email', value: 'fix@acme.in' });
  const note = await env.fake.waitFor((m) => /corrected the email field/.test(m.realtimeInput?.text ?? ''));
  assert.match(note.realtimeInput.text, /fix@acme\.in/);

  // the edited value counts toward finish_intake
  env.fake.send({ toolCall: { functionCalls: [
    { id: '1', name: 'save_field', args: { field: 'name', value: 'A' } },
    { id: '2', name: 'save_field', args: { field: 'problem', value: 'P' } },
  ] } });
  await c.waitFor((m) => m.type === 'field' && m.field === 'problem');
  env.fake.send(call('3', 'finish_intake', { next: ['demo'] }));
  assert.equal((await c.waitFor((m) => m.type === 'intake_complete')).lead.email, 'fix@acme.in');
});

test('session cap: wrap-up text turn, then ended:"cap" after the grace period', async (t) => {
  const { env, c } = await start({ env: { MAX_SESSION_SECONDS: '0.4', CAP_GRACE_SECONDS: '0.3' } }); t.after(env.stop);
  const started = Date.now();
  await env.fake.waitFor((m) => /Wrap up in one sentence/.test(m.realtimeInput?.text ?? ''));
  assert.ok(Date.now() - started >= 300, 'wrap-up is not sent early');
  assert.ok(!c.msgs.some((m) => m.type === 'ended'), 'not ended yet during grace');
  const ended = await c.waitFor((m) => m.type === 'ended');
  assert.equal(ended.reason, 'cap');
  assert.ok(Date.now() - started >= 650, 'closes only after cap + grace');
  await c.waitClosed();
  assert.equal(env.logs.find((l) => l.event === 'session_end').reason, 'cap');
});

test('idle timeout ends the session; client activity postpones it', async (t) => {
  const { env, c } = await start({ env: { IDLE_SECONDS: '0.4' } }); t.after(env.stop);
  for (let i = 0; i < 4; i++) { c.send({ type: 'text', text: 'still here' }); await sleepMs(200); }
  assert.ok(!c.msgs.some((m) => m.type === 'ended'), 'activity kept it alive past 0.4s');
  const ended = await c.waitFor((m) => m.type === 'ended', 1500);
  assert.equal(ended.reason, 'idle');
  await c.waitClosed();
});

test('unknown or malformed client messages get an error, never silence', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  c.send({ type: 'bogus' });
  assert.equal((await c.waitFor((m) => m.code === 'unknown_type')).type, 'error');
  c.send('not json');
  await c.waitFor((m) => m.code === 'bad_json');
  c.send({ nope: 1 });
  await c.waitFor((m) => m.code === 'bad_message');
  c.send({ type: 'text', text: 'x'.repeat(501) });
  await c.waitFor((m) => m.code === 'bad_text');
  c.send({ type: 'audio' });
  await c.waitFor((m) => m.code === 'bad_audio');
  c.send({ type: 'text', text: 'hello there' });
  await env.fake.waitFor((m) => m.realtimeInput?.text === 'hello there');
  assert.ok(!c.msgs.some((m) => m.type === 'ended'), 'session survives bad input');
});

test('stop ends the session with reason "stop"', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  c.send({ type: 'stop' });
  assert.equal((await c.waitFor((m) => m.type === 'ended')).reason, 'stop');
  await c.waitClosed();
});

test('upstream close surfaces error then ended:"error"', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  env.fake.closeAll(1011, 'upstream boom');
  await c.waitFor((m) => m.type === 'error' && m.code === 'upstream_closed');
  assert.equal((await c.waitFor((m) => m.type === 'ended')).reason, 'error');
  await c.waitClosed();
  assert.equal(env.app.sessions.size, 0, 'session slot is released');
});

test('a strict-upstream violation (1008) also ends the session as error', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  env.fake.send(call('q', 'save_field', { field: 'name', value: 'A' }));
  await c.waitFor((m) => m.type === 'field');
  env.fake.closeAll(1008, 'malformed');
  assert.equal((await c.waitFor((m) => m.type === 'ended')).reason, 'error');
});

test('logs carry no audio, transcripts, emails or tokens, and include usage', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  c.send({ type: 'audio', data: 'U0VDUkVUQVVESU8=' });
  env.fake.send({ inputTranscription: { text: 'SECRET TRANSCRIPT' } });
  env.fake.send({ serverContent: { modelTurn: { parts: [{ inlineData: { data: 'U0VDUkVUT1VU' } }] } } });
  env.fake.send(call('1', 'save_field', { field: 'email', value: 'private@person.in' }));
  env.fake.send({ usageMetadata: { totalTokenCount: 321 } });
  await c.waitFor((m) => m.type === 'field');
  c.send({ type: 'stop' });
  await c.waitFor((m) => m.type === 'ended');
  await sleepMs(50);
  const all = JSON.stringify(env.logs);
  for (const secret of ['SECRET TRANSCRIPT', 'private@person.in', 'U0VDUkVUQVVESU8=', 'U0VDUkVUT1VU', 'test-secret']) {
    assert.ok(!all.includes(secret), `log leaked ${secret}`);
  }
  const end = env.logs.find((l) => l.event === 'session_end');
  assert.equal(end.reason, 'stop');
  assert.equal(end.usage.totalTokenCount, 321);
  assert.ok(typeof end.durationMs === 'number' && end.sessionId);
});

const listeningCount = (c) => c.msgs.filter((m) => m.type === 'state' && m.state === 'listening').length;
const waitListening = (c, n) => c.waitFor(() => listeningCount(c) >= n, 1500);

test('listening follows a turn that ends in a toolCall, then a follow-up turn', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;
  const before = listeningCount(c);
  fake.send({ serverContent: { modelTurn: { parts: [{ inlineData: { data: 'QQ==' } }] } } });
  fake.send(call('t1', 'save_field', { field: 'name', value: 'A' }));
  await fake.waitFor(toolResp('t1'));
  fake.send({ serverContent: { modelTurn: { parts: [{ inlineData: { data: 'Qg==' } }] }, turnComplete: true } }); // modelTurn + turnComplete in one message
  await waitListening(c, before + 1);
  const last = c.msgs.filter((m) => m.type === 'state').at(-1);
  assert.equal(last.state, 'listening');
});

test('every turnComplete and interrupted emits a fresh listening, even without audio or a state change', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;
  let n = listeningCount(c);
  for (let i = 0; i < 3; i++) { // three text-only turns, transcription but no audio
    c.send({ type: 'text', text: `turn ${i}` });
    fake.send({ serverContent: { outputTranscription: { text: `reply ${i}` } } });
    fake.send({ serverContent: { turnComplete: true } });
    await waitListening(c, ++n);
  }
  fake.send({ serverContent: { interrupted: true } });
  await waitListening(c, ++n);
  fake.send({ serverContent: { interrupted: true } });
  await waitListening(c, ++n);
});

test('setup frame carries a female voice and language, overridable by env', async (t) => {
  const { env } = await start(); t.after(env.stop);
  const setup = env.fake.received[0].setup.generationConfig.speechConfig;
  assert.equal(setup.voiceConfig.prebuiltVoiceConfig.voiceName, 'Kore');
  assert.equal(setup.languageCode, 'en-US');
  const o = await start({ env: { VOICE_NAME: 'Aoede', VOICE_LANGUAGE: 'en-GB' } }); t.after(o.env.stop);
  const s2 = o.env.fake.received[0].setup.generationConfig.speechConfig;
  assert.deepEqual([s2.voiceConfig.prebuiltVoiceConfig.voiceName, s2.languageCode], ['Aoede', 'en-GB']);
});

test('setup tools: function declarations plus googleSearch by default, GOOGLE_SEARCH=0 drops only the search', async (t) => {
  const { env } = await start(); t.after(env.stop);
  const tools = env.fake.received[0].setup.tools;
  assert.deepEqual(tools[0].functionDeclarations.map((d) => d.name).sort(), ['finish_intake', 'navigate', 'save_field']);
  assert.ok(tools.some((x) => x.googleSearch && Object.keys(x.googleSearch).length === 0), 'googleSearch tool present');
  const o = await start({ env: { GOOGLE_SEARCH: '0' } }); t.after(o.env.stop);
  const off = o.env.fake.received[0].setup.tools;
  assert.equal(off.length, 1);
  assert.ok(off[0].functionDeclarations.length === 3 && !off.some((x) => x.googleSearch));
});

test('instructions: infer email from name, no letter-by-letter, no blanket knowledge ban', async () => {
  const text = readFileSync(new URL('../instructions.md', import.meta.url), 'utf8');
  assert.ok(!/letter by letter/i.test(text));
  assert.ok(!/instead of improvising/i.test(text));
  assert.match(text, /Infer before asking/);
  assert.match(text, /suyashraj@gmail\.com/);
  assert.match(text, /Read it back ONCE/);
  assert.match(text, /Never mention searching, Google/);
});

const silent = { SILENCE_SECONDS: '0.3', SILENCE_GRACE_SECONDS: '0.3' };
const isNudge = (m) => m.realtimeInput?.text?.includes('silent for 10 seconds');
const turnDone = { serverContent: { turnComplete: true } };
const said = { serverContent: { inputTranscription: { text: 'hi' } } };
const audio = { serverContent: { modelTurn: { parts: [{ inlineData: { data: 'AAAA', mimeType: 'audio/pcm;rate=24000' } }] } } };

test('silence after turnComplete ends with reason "silence" and closes', async (t) => {
  const { env, c } = await start({ env: silent }); t.after(env.stop);
  env.fake.send(turnDone);
  const ended = await c.waitFor((m) => m.type === 'ended', 1500);
  assert.equal(ended.reason, 'silence');
  await c.waitClosed();
  assert.equal(env.logs.find((l) => l.event === 'session_end').reason, 'silence');
});

test('visitor speech before expiry cancels the silence timer', async (t) => {
  const { env, c } = await start({ env: silent }); t.after(env.stop);
  env.fake.send(turnDone);
  await sleepMs(150);
  env.fake.send(said);
  await c.expectNone((m) => m.type === 'ended', 700);
});

test('silence timer does not run while Donna is speaking or calling a tool', async (t) => {
  const { env, c } = await start({ env: silent }); t.after(env.stop);
  env.fake.send(turnDone);
  await sleepMs(150);
  env.fake.send(audio);
  await c.expectNone((m) => m.type === 'ended', 700);
  env.fake.send(turnDone);
  await sleepMs(150);
  env.fake.send(call('t1', 'save_field', { field: 'name', value: 'Asha' }));
  await c.expectNone((m) => m.type === 'ended', 700);
  env.fake.send(turnDone);
  assert.equal((await c.waitFor((m) => m.type === 'ended', 1500)).reason, 'silence');
});

test('client text and field_edit frames reset the silence timer', async (t) => {
  const { env, c } = await start({ env: silent }); t.after(env.stop);
  env.fake.send(turnDone);
  await sleepMs(150);
  c.send({ type: 'text', text: 'typing here' });
  await c.expectNone((m) => m.type === 'ended', 600);
  env.fake.send(turnDone);
  await sleepMs(150);
  c.send({ type: 'field_edit', field: 'name', value: 'Asha Rao' });
  await c.expectNone((m) => m.type === 'ended', 600);
});

test('first silence nudges Donna instead of ending; second quiet window ends', async (t) => {
  const { env, c } = await start({ env: { SILENCE_SECONDS: '0.2', SILENCE_GRACE_SECONDS: '0.6' } }); t.after(env.stop);
  env.fake.send(turnDone);
  await env.fake.waitFor(isNudge);
  assert.ok(!c.msgs.some((m) => m.type === 'ended'), 'not ended by the first expiry');
  assert.equal(env.fake.received.filter(isNudge).length, 1);
  env.fake.send(audio);
  env.fake.send(turnDone); // Donna's nudge turn completes -> grace timer
  assert.equal((await c.waitFor((m) => m.type === 'ended', 1500)).reason, 'silence');
  assert.equal(env.fake.received.filter(isNudge).length, 1, 'only one nudge per episode');
});

test('visitor speech after the nudge resets to stage 1 (a new nudge, not an end)', async (t) => {
  const { env, c } = await start({ env: { SILENCE_SECONDS: '0.2', SILENCE_GRACE_SECONDS: '0.5' } }); t.after(env.stop);
  env.fake.send(turnDone);
  await env.fake.waitFor(isNudge);
  env.fake.send(said);
  env.fake.send(turnDone);
  await c.expectNone((m) => m.type === 'ended', 350); // would be in grace, but stage reset -> first timer is 0.2s then nudge
  await sleepMs(150);
  await env.fake.waitFor((m) => isNudge(m) && m !== env.fake.received.find(isNudge));
  assert.ok(!c.msgs.some((m) => m.type === 'ended'));
});

const resumeFields = { name: 'Asha Rao', company: 'Acme', industry: 'Retail' };

test('resume frame seeds the lead, echoes fields and tells the greeting what is saved', async (t) => {
  const env = await boot(); t.after(env.stop);
  const { ticket } = await env.ticket();
  const { client: c } = await env.tryConnect(ticket);
  c.send({ type: 'resume', fields: { ...resumeFields, bogus: 'x', email: 'not-an-email' } });
  await c.waitFor((m) => m.type === 'ready');
  assert.deepEqual(c.msgs.filter((m) => m.type === 'field').map((m) => [m.field, m.value]), [['name', 'Asha Rao'], ['company', 'Acme'], ['industry', 'Retail']]);
  const g = await env.fake.waitFor((m) => m.realtimeInput?.text?.includes('returning visitor'));
  const text = g.realtimeInput.text;
  assert.match(text, /name=Asha Rao/);
  assert.match(text, /company=Acme/);
  assert.match(text, /continue with what is missing: email, website, problem, volume/);
  assert.ok(!text.includes('bogus') && !text.includes('not-an-email'), 'invalid fields dropped');
  // seeded fields count toward finish_intake
  env.fake.send(call('e', 'save_field', { field: 'email', value: 'a@acme.in' }));
  env.fake.send(call('p', 'save_field', { field: 'problem', value: 'Missed calls' }));
  await c.waitFor((m) => m.type === 'field' && m.field === 'problem');
  env.fake.send(call('f', 'finish_intake', { next: ['plan'] }));
  assert.deepEqual((await c.waitFor((m) => m.type === 'intake_complete')).lead.name, 'Asha Rao');
});

test('resume that is not the first frame is ignored', async (t) => {
  const env = await boot(); t.after(env.stop);
  const { ticket } = await env.ticket();
  const { client: c } = await env.tryConnect(ticket);
  c.send({ type: 'stop_nothing_just_unknown' });
  c.send({ type: 'resume', fields: resumeFields });
  await c.waitFor((m) => m.type === 'ready');
  await sleepMs(100);
  assert.ok(!c.msgs.some((m) => m.type === 'field'));
  await env.fake.waitFor((m) => m.realtimeInput?.text === 'Hello');
});

test('no resume frame: greeting goes out after the wait', async (t) => {
  const env = await boot(); t.after(env.stop);
  const { ticket } = await env.ticket();
  const { client: c } = await env.tryConnect(ticket);
  await c.waitFor((m) => m.type === 'ready', 2000);
  await env.fake.waitFor((m) => m.realtimeInput?.text === 'Hello');
});

test('Devanagari name/company/industry are rejected so the model resends in Latin script; Latin accepted', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  env.fake.send(call('d1', 'save_field', { field: 'name', value: 'नीरव मेहता' }));
  const bad = respOf(await env.fake.waitFor(toolResp('d1')), 'd1');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /Latin script/);
  env.fake.send(call('d2', 'save_field', { field: 'industry', value: 'ज्वेलरी' }));
  assert.equal(respOf(await env.fake.waitFor(toolResp('d2')), 'd2').ok, false);
  env.fake.send(call('d3', 'save_field', { field: 'name', value: 'Nirav Mehta' }));
  assert.equal(respOf(await env.fake.waitFor(toolResp('d3')), 'd3').ok, true);
  env.fake.send(call('d4', 'save_field', { field: 'problem', value: 'कॉल्स मिस हो जाती हैं' }));
  assert.equal(respOf(await env.fake.waitFor(toolResp('d4')), 'd4').ok, true, 'problem may stay mixed');
  assert.deepEqual(c.msgs.filter((m) => m.type === 'field').map((m) => m.field), ['name', 'problem']);
});

// ---- finish_intake next-step choice
const SAVE3 = (id) => ({ toolCall: { functionCalls: [
  { id: `${id}1`, name: 'save_field', args: { field: 'name', value: 'Asha Rao' } },
  { id: `${id}2`, name: 'save_field', args: { field: 'email', value: 'asha@acme.in' } },
  { id: `${id}3`, name: 'save_field', args: { field: 'problem', value: 'Missed calls after six.' } },
] } });

async function saved(env, c, id) {
  env.fake.send(SAVE3(id));
  await c.waitFor((m) => m.type === 'field' && m.field === 'problem');
}

test('finish_intake without next is rejected and nothing is recorded', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  for (const [id, args] of [['n1', {}], ['n2', { next: [] }], ['n3', { next: 'plan' }]]) {
    env.fake.send(call(id, 'finish_intake', args));
    const r = respOf(await env.fake.waitFor(toolResp(id)), id);
    assert.equal(r.ok, false);
    assert.match(r.error, /Ask the visitor which they want/);
  }
  await c.expectNone((m) => m.type === 'intake_complete');
});

test('finish_intake rejects an unknown next value', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('u', 'finish_intake', { next: ['plan', 'email_me_everything'] }));
  assert.equal(respOf(await env.fake.waitFor(toolResp('u')), 'u').ok, false);
  await c.expectNone((m) => m.type === 'intake_complete');
});

test('finish_intake demo-only records the lead for the client and navigates nothing itself', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('d', 'finish_intake', { next: ['demo'] }));
  const done = await c.waitFor((m) => m.type === 'intake_complete');
  assert.deepEqual(done.next, ['demo']);
  assert.equal(done.lead.email, 'asha@acme.in');
  const r = respOf(await env.fake.waitFor(toolResp('d')), 'd');
  assert.equal(r.ok, true);
  assert.match(r.then.join(' '), /navigate with route demos/);
  await c.expectNone((m) => m.type === 'navigate');
});

// ---- plan = open the Automation Plan Generator (no email, no webhook)
const withSpy = () => { const calls = []; return { calls, fetchFn: (...a) => { calls.push(a); return Promise.reject(new Error('no fetch expected')); } }; };
const PLAN_BASE = 'https://voxdonna.com/automation-plan.html';

test('finish_intake plan emits a navigate with the exact planner url and posts nothing', async (t) => {
  const spy = withSpy();
  const { env, c } = await start({ webhook: true, overrides: { fetchFn: spy.fetchFn } }); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('v', 'save_field', { field: 'volume', value: '1,200 calls a month' }));
  await c.waitFor((m) => m.type === 'field' && m.field === 'volume');
  env.fake.send(call('p', 'finish_intake', { next: ['plan', 'plan'], industry_id: 'jewellery-retail' }));
  const done = await c.waitFor((m) => m.type === 'intake_complete');
  assert.deepEqual(done.next, ['plan'], 'deduped');
  const nav = await c.waitFor((m) => m.type === 'navigate');
  assert.deepEqual(nav, { type: 'navigate', route: 'automation_plan', url: `${PLAN_BASE}?industry=jewellery-retail&volume=500-2000` });
  const r = respOf(await env.fake.waitFor(toolResp('p')), 'p');
  assert.equal(r.ok, true);
  assert.match(r.then[0], /do NOT call navigate/);
  assert.doesNotMatch(JSON.stringify(r), /inbox|email|pdf/i);
  await sleepMs(150);
  assert.equal(spy.calls.length, 0, 'no outbound fetch for plan');
  assert.equal(env.hook.requests.length, 0, 'no webhook even when one is configured');
});

test('finish_intake plan: unknown or missing industry_id and unparseable volume drop their params', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('v', 'save_field', { field: 'volume', value: 'about two thousand' }));
  await c.waitFor((m) => m.type === 'field' && m.field === 'volume');
  env.fake.send(call('p', 'finish_intake', { next: ['plan'], industry_id: 'underwater-basket-weaving' }));
  const nav = await c.waitFor((m) => m.type === 'navigate');
  assert.equal(nav.url, PLAN_BASE);
  assert.equal(respOf(await env.fake.waitFor(toolResp('p')), 'p').ok, true);
});

test('finish_intake plan + call: the call wins, the planner does not open', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('pc', 'finish_intake', { next: ['plan', 'call'], industry_id: 'real-estate' }));
  const done = await c.waitFor((m) => m.type === 'intake_complete');
  assert.deepEqual(done.next, ['plan', 'call']);
  const r = respOf(await env.fake.waitFor(toolResp('pc')), 'pc');
  assert.equal(r.then.length, 1);
  assert.match(r.then[0], /book_meeting/);
  await c.expectNone((m) => m.type === 'navigate');
});

test('finish_intake plan + demo opens the planner', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('pd', 'finish_intake', { next: ['demo', 'plan'], industry_id: 'real-estate' }));
  const nav = await c.waitFor((m) => m.type === 'navigate');
  assert.equal(nav.url, `${PLAN_BASE}?industry=real-estate`);
  const r = respOf(await env.fake.waitFor(toolResp('pd')), 'pd');
  assert.doesNotMatch(r.then.join(' '), /route demos/);
});

test('a later finish_intake adding plan after demo-only re-opens the planner without a second lead', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  await saved(env, c, 's');
  env.fake.send(call('a', 'finish_intake', { next: ['demo'] }));
  await c.waitFor((m) => m.type === 'intake_complete');

  env.fake.send(call('b', 'finish_intake', { next: ['plan'], industry_id: 'dental-practices' }));
  const nav = await c.waitFor((m) => m.type === 'navigate');
  assert.equal(nav.url, `${PLAN_BASE}?industry=dental-practices`);
  assert.equal(c.msgs.filter((m) => m.type === 'intake_complete').length, 1);
  env.fake.send(call('d', 'finish_intake', { next: ['call'] }));
  assert.equal(respOf(await env.fake.waitFor(toolResp('d')), 'd').alreadySubmitted, true);
});

test('book_meeting is a valid navigate route mapped to the booking page', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  env.fake.send(call('bm', 'navigate', { route: 'book_meeting' }));
  const nav = await c.waitFor((m) => m.type === 'navigate');
  assert.equal(nav.route, 'book_meeting');
  assert.equal(nav.url, 'https://tidycal.com/rajsuyash/discovery-call-for-ai-voice-agent');
});

test('navigate guard: mid-intake navigate needs the visitor to have asked; finish_intake lifts it', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  const { fake } = env;
  const navs = () => c.msgs.filter((m) => m.type === 'navigate').length;

  // Mid-intake after an intake answer: rejected, no event.
  fake.send(call('s1', 'save_field', { field: 'name', value: 'Asha' }));
  await fake.waitFor(toolResp('s1'));
  fake.send({ inputTranscription: { text: 'Jewellery retail' } });
  await c.waitFor((m) => m.type === 'caption' && m.who === 'user');
  fake.send(call('n1', 'navigate', { route: 'jewellers' }));
  const rej = respOf(await fake.waitFor(toolResp('n1')), 'n1');
  assert.equal(rej.ok, false);
  assert.match(rej.error, /Only navigate when the visitor asks/);
  assert.equal(navs(), 0);

  // Visitor asks (new utterance after a turn boundary, chunks accumulate): allowed.
  fake.send({ serverContent: { turnComplete: true } });
  fake.send({ inputTranscription: { text: 'show me' } });
  fake.send({ inputTranscription: { text: ' a demo' } });
  await c.waitFor((m) => m.type === 'caption' && m.text === ' a demo');
  fake.send(call('n2', 'navigate', { route: 'demos' }));
  assert.equal(respOf(await fake.waitFor(toolResp('n2')), 'n2').ok, true);
  assert.equal(navs(), 1);

  // Typed text counts too, in Hinglish as well.
  c.send({ type: 'text', text: 'Jewellery retail' });
  fake.send(call('n3', 'navigate', { route: 'jewellers' }));
  assert.equal(respOf(await fake.waitFor(toolResp('n3')), 'n3').ok, false);
  c.send({ type: 'text', text: 'pricing dikhao' });
  fake.send(call('n4', 'navigate', { route: 'pricing' }));
  assert.equal(respOf(await fake.waitFor(toolResp('n4')), 'n4').ok, true);

  // After finish_intake the guard is off, whatever was last said.
  for (const [i, [f, v]] of [['email', 'a@b.co'], ['problem', 'calls drop']].entries()) {
    fake.send(call(`s${i + 2}`, 'save_field', { field: f, value: v }));
    await fake.waitFor(toolResp(`s${i + 2}`));
  }
  fake.send(call('f1', 'finish_intake', { next: ['demo'] }));
  assert.equal(respOf(await fake.waitFor(toolResp('f1')), 'f1').ok, true);
  c.send({ type: 'text', text: 'Jewellery retail' });
  fake.send(call('n5', 'navigate', { route: 'demos' }));
  assert.equal(respOf(await fake.waitFor(toolResp('n5')), 'n5').ok, true);
});

const donnaSays = (text) => ({ serverContent: { modelTurn: { parts: [{ inlineData: { data: 'AAAA', mimeType: 'audio/pcm;rate=24000' } }] }, outputTranscription: { text } } });
const audioCount = (c) => c.msgs.filter((m) => m.type === 'audio').length;

test('navigate: transition line after the call plays, the next turn is dropped, no nudge, backstop ends', async (t) => {
  const { env, c } = await start({ env: { SILENCE_SECONDS: '0.2', SILENCE_GRACE_SECONDS: '0.3', NAV_END_SECONDS: '0.9' } }); t.after(env.stop);
  const { fake } = env;
  fake.send(call('n1', 'navigate', { route: 'demos' }));
  await c.waitFor((m) => m.type === 'navigate');
  await fake.waitFor(toolResp('n1'));

  fake.send(donnaSays('Opening the demo.'));
  await c.waitFor((m) => m.type === 'caption' && m.text === 'Opening the demo.');
  assert.equal(audioCount(c), 1, 'transition line forwarded');
  fake.send({ serverContent: { turnComplete: true } });
  await c.waitFor((m) => m.type === 'state' && m.state === 'listening');

  fake.send(donnaSays('To continue our setup, what is your email?'));
  await c.expectNone((m) => m.type === 'caption' && /continue our setup/.test(m.text), 300);
  assert.equal(audioCount(c), 1, 'later model audio is not forwarded');
  assert.equal(fake.received.filter((m) => m.realtimeInput?.text?.includes('silent for')).length, 0, 'no silence nudge');
  assert.ok(!c.msgs.some((m) => m.type === 'ended'), 'socket stays open so the client redirect finishes');
  assert.equal((await c.waitFor((m) => m.type === 'ended', 1500)).reason, 'navigate');
});

test('navigate after the line already played: further model output is dropped immediately', async (t) => {
  const { env, c } = await start({ env: { SILENCE_SECONDS: '0.2' } }); t.after(env.stop);
  const { fake } = env;
  fake.send(donnaSays('Opening pricing.'));
  await c.waitFor((m) => m.type === 'caption' && m.text === 'Opening pricing.');
  fake.send(call('n1', 'navigate', { route: 'pricing' }));
  await fake.waitFor(toolResp('n1'));
  fake.send(donnaSays('Anything else?'));
  await c.expectNone((m) => m.type === 'caption' && m.text === 'Anything else?', 300);
  assert.equal(audioCount(c), 1);
  fake.send({ serverContent: { turnComplete: true } });
  await c.waitFor((m) => m.type === 'state' && m.state === 'listening');
  await sleepMs(500);
  assert.equal(fake.received.filter((m) => m.realtimeInput?.text?.includes('silent for')).length, 0, 'no nudge after navigate');
});

test('finish_intake plan opens the planner and gets the same go-quiet treatment', async (t) => {
  const { env, c } = await start({ env: { SILENCE_SECONDS: '0.2' } }); t.after(env.stop);
  const { fake } = env;
  for (const [i, [f, v]] of [['name', 'Asha'], ['email', 'a@b.co'], ['problem', 'calls drop']].entries()) {
    fake.send(call(`s${i}`, 'save_field', { field: f, value: v }));
    await fake.waitFor(toolResp(`s${i}`));
  }
  fake.send(call('f1', 'finish_intake', { next: ['plan'] }));
  await c.waitFor((m) => m.type === 'navigate');
  fake.send(donnaSays('Opening your automation plan.'));
  fake.send({ serverContent: { turnComplete: true } });
  await c.waitFor((m) => m.type === 'caption' && m.final);
  fake.send(donnaSays('And your phone number?'));
  await c.expectNone((m) => m.type === 'caption' && /phone number/.test(m.text), 300);
  assert.equal(fake.received.filter((m) => m.realtimeInput?.text?.includes('silent for')).length, 0);
});

test('a rejected navigate does not silence Donna', async (t) => {
  const { env, c } = await start(); t.after(env.stop);
  env.fake.send(call('n1', 'navigate', { route: 'nowhere' }));
  await env.fake.waitFor(toolResp('n1'));
  env.fake.send(donnaSays('Still here.'));
  await c.waitFor((m) => m.type === 'caption' && m.text === 'Still here.');
});
