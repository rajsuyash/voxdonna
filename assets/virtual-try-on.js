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
let loadingImage = false;
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
  $('start').disabled = busy || loadingImage || !$('consent').checked;
  $('stop').disabled = !busy;
  $('apply').disabled = !session || updating || loadingImage;
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
  loadingImage = false;
  if (imageURL) URL.revokeObjectURL(imageURL);
  imageURL = '';
  image = null;
  $('garment').value = '';
  $('reference-preview').removeAttribute('src');
  $('reference-preview').hidden = true;
  $('remove-image').hidden = true;
  controls();
}

const samplePrompts = [
  "Substitute the current top with a men's navy blue long-sleeve cotton shirt with a pointed collar and white buttons.",
  "Substitute the current top with a men's forest green plain short-sleeve crew-neck cotton T-shirt.",
  "Substitute the current top with a men's camel wool single-breasted knee-length coat with notch lapels and dark buttons.",
  "Substitute the current top with a women's ivory satin long-sleeve collared blouse with concealed buttons and a relaxed fit.",
  "Substitute the current top with a women's dusty rose pink plain short-sleeve crew-neck cotton T-shirt.",
  "Substitute the current top with a women's charcoal grey double-breasted knee-length wool coat with broad lapels and black buttons.",
  "Add a matching pair of medium polished yellow gold hoop earrings, one on each earlobe.",
  "Add matching yellow gold drop earrings with round white gemstone studs and single teardrop white pearls, one on each earlobe.",
  "Add a delicate yellow gold cable-link necklace with a round gold disc pendant resting at the upper chest.",
  "Add a delicate yellow gold necklace with an oval emerald-green gemstone pendant in a thin gold bezel at the upper chest.",
  "Add a yellow gold curb-link chain necklace around the neck, without a pendant.",
  "Add a thin silver rope chain necklace around the neck, without a pendant.",
];

$('samples').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-sample]');
  if (!button || updating) return;
  const index = Number(button.dataset.sample);
  clearImage();
  const current = imageGeneration;
  loadingImage = true;
  controls();
  status('Loading the reference image…');
  try {
    const sheet = new Image();
    sheet.src = index < 6 ? '/assets/virtual-try-on-samples.png' : '/assets/virtual-try-on-jewellery.png';
    await sheet.decode();
    if (current !== imageGeneration) return;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 512;
    const width = sheet.naturalWidth / 3;
    const height = sheet.naturalHeight / 2;
    const cell = index % 6;
    canvas.getContext('2d').drawImage(sheet, (cell % 3) * width, Math.floor(cell / 3) * height, width, height, 0, 0, 512, 512);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.92));
    if (current !== imageGeneration) return;
    if (!blob) throw new Error('Image conversion failed.');
    image = new File([blob], 'sample-' + index + '.jpg', { type: 'image/jpeg' });
    imageURL = URL.createObjectURL(image);
    $('reference-preview').src = imageURL;
    $('reference-preview').hidden = false;
    $('remove-image').hidden = false;
    $('prompt').value = samplePrompts[index];
    document.querySelectorAll('.look').forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
    const framing = index < 6 ? '' : index < 8 ? ' Keep your ears visible and tuck hair back.' : ' Keep your neck and upper chest visible.';
    status((session ? 'Sample ready. Press Apply look to try it on.' : 'Sample ready. Start your camera to try it on.') + framing);
  } catch {
    if (current === imageGeneration) status('The sample image could not load. Try again or upload your own item.', true);
  } finally {
    if (current === imageGeneration) { loadingImage = false; controls(); }
  }
});

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
