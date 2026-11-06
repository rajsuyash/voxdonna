// Copper ring: silent loop video over a still. Pace follows state, scale follows audio level.
const PACE = { speaking: 1.65, thinking: 1.2, listening: 1.2 };

export function initSoundform(root) {
  const holder = root.querySelector('.dh-object');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const video = document.createElement('video');
  video.className = 'dh-motion';
  Object.assign(video, { muted: true, defaultMuted: true, loop: true, playsInline: true, disablePictureInPicture: true, disableRemotePlayback: true });
  video.setAttribute('aria-hidden', 'true');
  let inView = false;
  let mode = 'ready';

  const shouldPlay = () => inView && !document.hidden && !reduced.matches;
  const showStill = () => holder.classList.remove('is-motion');

  function sync() {
    video.playbackRate = PACE[mode] || 1;
    if (!shouldPlay()) { video.pause(); showStill(); return; }
    if (!video.isConnected) { video.src = new URL('donna-breath.mp4?v=20261106d', import.meta.url).href; holder.append(video); }
    video.play().catch(showStill);
  }

  video.addEventListener('playing', () => { if (shouldPlay()) holder.classList.add('is-motion'); });
  for (const ev of ['pause', 'error', 'waiting']) video.addEventListener(ev, showStill);
  new IntersectionObserver(([e]) => { inView = e.isIntersecting; sync(); }).observe(holder);
  reduced.addEventListener('change', sync);
  document.addEventListener('visibilitychange', sync);

  return {
    setMode(next) { mode = next; video.playbackRate = PACE[mode] || 1; },
    setLevel(level) { if (!reduced.matches) root.style.setProperty('--dh-lvl', Math.min(1, Math.max(0, level)).toFixed(3)); },
  };
}
