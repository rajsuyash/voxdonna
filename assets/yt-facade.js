/* Swap a .yt-frame button for a youtube-nocookie iframe on click. */
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.yt-play');
  if (!btn) return;
  var frame = btn.closest('.yt-frame');
  var id = frame && frame.getAttribute('data-yt');
  if (!id || !/^[\w-]{11}$/.test(id)) return;
  var f = document.createElement('iframe');
  f.src = 'https://www.youtube-nocookie.com/embed/' + id + '?autoplay=1&rel=0&playsinline=1';
  f.title = frame.getAttribute('data-title') || 'Video';
  f.allow = 'autoplay; encrypted-media; picture-in-picture; fullscreen';
  f.allowFullscreen = true;
  frame.replaceChildren(f);
  f.focus();
});
