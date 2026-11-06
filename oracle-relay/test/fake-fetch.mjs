// Fake fetch that refuses any URL it was not told about. Handlers: { [url]: (init) => ({status, body}) }.
export function fakeFetch(handlers) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const h = handlers[url];
    if (!h) throw new Error(`fakeFetch: unexpected URL ${url}`);
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, init, body });
    const { status = 200, body: out = {} } = await h({ url, init, body });
    return { ok: status >= 200 && status < 300, status, json: async () => out, text: async () => JSON.stringify(out) };
  };
  fn.calls = calls;
  return fn;
}

export const VERTEX_URL = (model = 'gemini-3.8-flash', project = 'voxdonna-oracle', location = 'global') =>
  `https://${location === 'global' ? '' : `${location}-`}aiplatform.googleapis.com/v1/projects/${project}/locations/${location}/publishers/google/models/${model}:generateContent`;
export const RESEND_URL = 'https://api.resend.com/emails';

export const vertexReply = (plan) => ({ status: 200, body: { candidates: [{ content: { parts: [{ text: JSON.stringify(plan) }] } }] } });
