const RESEND_URL = 'https://api.resend.com/emails';

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function attachmentName(lead) {
  const base = String(lead.company || lead.name || 'plan').normalize('NFKD').replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return `VoxDonna-plan-${base || 'plan'}.pdf`;
}

export function buildEmail({ lead, pdf, plan }) {
  const first = String(lead.name || '').trim().split(/\s+/)[0] || 'there';
  const top = plan.picks[0];
  const text = `Hi ${first},

Your plan is attached. One page of what to automate first, one page of how to start.

Number one: ${top.title}. ${top.first_step}

If you want it done rather than described, reply to this email or book a call: https://voxdonna.com/#contact

Donna
VoxDonna`;
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#111">
<p>Hi ${escapeHtml(first)},</p>
<p>Your plan is attached. One page of what to automate first, one page of how to start.</p>
<p><strong>Number one:</strong> ${escapeHtml(top.title)}. ${escapeHtml(top.first_step)}</p>
<p>If you want it done rather than described, reply to this email or <a href="https://voxdonna.com/#contact">book a call</a>.</p>
<p>Donna<br>VoxDonna</p>
</div>`;
  return {
    from: 'VoxDonna <hello@send.voxdonna.com>',
    reply_to: 'hello@voxdonna.com',
    to: [lead.email],
    bcc: ['hello@voxdonna.com'],
    subject: 'Your automation plan. Start with one thing.',
    text,
    html,
    attachments: [{ filename: attachmentName(lead), content: Buffer.from(pdf).toString('base64') }],
  };
}

// Throws Error('resend_<status>') on non-2xx; the message carries the status only.
export async function sendPlanEmail({ apiKey, lead, pdf, plan, fetchFn = fetch }) {
  const res = await fetchFn(RESEND_URL, {
    method: 'POST',
    headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify(buildEmail({ lead, pdf, plan })),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`resend_${res.status}`);
  return true;
}
