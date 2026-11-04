const $ = (id) => document.getElementById(id);
const prompts = [
  'Substitute the current top with a navy blue tailored blazer, worn over a light blue dress shirt.',
  'Substitute the current top with a red leather jacket with a zip front and a fitted silhouette.',
  'Substitute the current top with a charcoal grey cotton hoodie with a relaxed fit and a kangaroo pocket.',
  'Substitute the current top with a blue denim jacket with a relaxed fit, chest pockets and metal buttons.',
];
let session = null;
let stream = null;
let image = null;
let imageURL = '';
let generation = 0;
let imageGeneration = 0;
let busy = false;
let updating = false;
let deadline = 0;
let timer = null;

function publicError(message) {
  return Object.assign(new Error(message), { publicMessage: message });
}

function status(message, error = false) {
  $('status').textContent = message;
  $('status').dataset.error = String(error);
}

function controls() {
  $('start').disabled = busy || !$('consent').checked;
  $('stop').disabled = !busy;
  $('apply').disabled = !session || updating;
  $('consent').disabled = busy;
  $('garment').disabled = updating;
  $('remove-image').disabled = updating;
  $('prompt').disabled = updating;
  document.querySelectorAll('.look').forEach((button) => { button.disabled = updating; });
}

function stop(message = 'Camera stopped. Your next look is ready when you are.', error = false) {
  generation++;
  clearInterval(timer);
  const previous = session;
  session = null;
  previous?.disconnect();
  stream?.getTracks().forEach((track) => track.stop());
  stream = null;
  $('output').srcObject?.getTracks().forEach((track) => track.stop());
  $('output').srcObject = null;
  $('original').srcObject = null;
  $('original-wrap').hidden = true;
  $('placeholder').hidden = false;
  $('timer').textContent = '2-minute demo';
  busy = false;
  updating = false;
  controls();
  status(message, error);
}

function state() {
  const prompt = $('prompt').value.trim();
  if (!prompt && !image) throw publicError('Describe a look or upload a garment image first.');
  return { ...(prompt ? { prompt } : {}), ...(image ? { image } : {}), enhance: false };
}

function clearImage() {
  imageGeneration++;
  if (imageURL) URL.revokeObjectURL(imageURL);
  imageURL = '';
  image = null;
  $('garment').value = '';
  $('reference-preview').removeAttribute('src');
  $('reference-preview').hidden = true;
  $('remove-image').hidden = true;
}

$('consent').addEventListener('change', controls);
$('stop').addEventListener('click', () => stop());
$('remove-image').addEventListener('click', () => {
  clearImage();
  status('Reference removed. Apply the look to update your session.');
});
$('looks').addEventListener('click', (event) => {
  const button = event.target.closest('[data-look]');
  if (!button || updating) return;
  clearImage();
  $('prompt').value = prompts[Number(button.dataset.look)];
  document.querySelectorAll('.look').forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
  status(session ? 'Look selected. Press Apply look to try it on.' : 'Look selected. Start your camera when ready.');
});

$('garment').addEventListener('change', async () => {
  const file = $('garment').files[0];
  clearImage();
  if (!file) return;
  const current = imageGeneration;
  try {
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type) || file.size > 8 * 1024 * 1024) {
      throw new Error('Choose a JPG, PNG or WebP image smaller than 8 MB.');
    }
    const bitmap = await createImageBitmap(file);
    if (current !== imageGeneration) { bitmap.close(); return; }
    const width = bitmap.width;
    const height = bitmap.height;
    bitmap.close();
    if (width < 128 || height < 128 || width * height > 25000000) {
      throw new Error('Choose an image at least 128 × 128 pixels and below 25 megapixels.');
    }
    image = file;
    imageURL = URL.createObjectURL(file);
    $('reference-preview').src = imageURL;
    $('reference-preview').hidden = false;
    $('remove-image').hidden = false;
    $('prompt').value = '';
    $('prompt').placeholder = 'For example: Substitute the current top with the cream cable-knit sweater shown in the reference image.';
    document.querySelectorAll('.look').forEach((item) => item.setAttribute('aria-pressed', 'false'));
    status('Garment ready. Add a description, or try the image on its own.');
  } catch (error) {
    if (current === imageGeneration) status(error.message || 'This image could not be opened.', true);
  }
});

$('apply').addEventListener('click', async () => {
  const current = generation;
  try {
    const next = state();
    updating = true;
    controls();
    status('Applying your look…');
    await session.set(next);
    if (current === generation) status('Look applied. Move naturally and watch the preview.');
  } catch {
    if (current === generation) status('The look could not be applied. Check your description or image and try again.', true);
  } finally {
    if (current === generation) { updating = false; controls(); }
  }
});

$('start').addEventListener('click', async () => {
  if (busy || !$('consent').checked) return;
  const current = ++generation;
  busy = true;
  controls();
  try {
    const selected = state();
    if (!navigator.mediaDevices?.getUserMedia) throw publicError('Camera access needs HTTPS and a supported browser. Open this page in Chrome, Edge or Safari.');
    status('Loading the fitting room…');
    const { createDecartClient, models } = await import('https://esm.sh/@decartai/sdk@0.2.14?bundle');
    if (current !== generation) return;
    const model = models.realtime('lucy-vton-latest');
    status('Allow camera access to start your try-on.');
    const camera = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: 'user', width: model.width, height: model.height, frameRate: model.fps } });
    if (current !== generation) { camera.getTracks().forEach((track) => track.stop()); return; }
    stream = camera;
    stream.getVideoTracks()[0].addEventListener('ended', () => { if (current === generation) stop('Camera disconnected. Reconnect it and start again.', true); });
    $('original').srcObject = stream;
    $('original-wrap').hidden = false;
    status('Connecting your live try-on…');
    deadline = Date.now() + 120000;
    timer = setInterval(() => {
      const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      $('timer').textContent = `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')} remaining`;
      if (!remaining) stop('Your two-minute demo has ended. You can start a new session.');
    }, 500);
    const client = createDecartClient({ apiKeyProvider: async () => {
      if (current !== generation) throw new Error('Session stopped.');
      const response = await fetch('/virtual-try-on-token.php', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', cache: 'no-store', signal: AbortSignal.timeout(15000) });
      const data = await response.json();
      if (!response.ok) throw publicError(data.error || 'The fitting room could not connect. Try again shortly.');
      if (current !== generation) throw new Error('Session stopped.');
      return data.apiKey;
    } });
    const connected = await client.realtime.connect(stream, {
      model, mirror: true, retries: 0,
      initialState: { ...(selected.prompt ? { prompt: { text: selected.prompt, enhance: false } } : {}), ...(selected.image ? { image: selected.image } : {}) },
      onRemoteStream: (remote) => {
        if (current !== generation) { remote.getTracks().forEach((track) => track.stop()); return; }
        $('output').srcObject = remote;
        $('output').onloadeddata = () => { if (current === generation) $('placeholder').hidden = true; };
      },
    });
    if (current !== generation) { connected.disconnect(); return; }
    session = connected;
    session.on('connectionChange', (value) => {
      if (current !== generation) return;
      if (value === 'disconnected') stop('Session ended. Start again when you are ready.');
      else if (value === 'reconnecting') status('Connection interrupted. Reconnecting…');
      else if (value === 'generating' || value === 'connected') status('Live. Pick another look whenever you like.');
    });
    session.on('error', () => { if (current === generation) stop('The try-on connection ended. Check your network and try again.', true); });
    controls();
    status('Live. Pick another look whenever you like.');
  } catch (error) {
    if (current !== generation) return;
    const messages = { NotAllowedError: 'Camera permission was declined. Allow camera access in your browser, then try again.', NotFoundError: 'No camera found. Connect a camera and try again.', NotReadableError: 'Your camera is busy. Close other camera apps and try again.' };
    // SDK errors can contain connection URLs; only our own messages are shown verbatim.
    stop(messages[error.name] || error.publicMessage || 'The fitting room could not connect. Check your network or try again shortly.', true);
  }
});

document.addEventListener('visibilitychange', () => { if (document.hidden && busy) stop('Demo paused because you left this tab. Start again to continue.'); });
window.addEventListener('pagehide', () => { stop(); clearImage(); });
