(() => {
  'use strict';
  const script = document.currentScript;
  const measurementId = script && script.dataset.measurementId;
  if (!/^G-[A-Z0-9]{6,12}$/.test(measurementId || '') || document.getElementById('vd-analytics-settings')) return;
  const preferenceKey = 'voxdonna-analytics-consent-v1';
  const maxAge = 180 * 24 * 60 * 60 * 1000;
  let choice = null;
  try {
    const saved = JSON.parse(localStorage.getItem(preferenceKey));
    if (saved && Date.now() - saved.updated < maxAge && ['granted', 'denied'].includes(saved.value)) choice = saved.value;
  } catch (_) { /* Storage can be disabled by the browser. */ }
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  gtag('consent', 'default', {analytics_storage: choice || 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied'});
  let started = false;
  function start() {
    window['ga-disable-' + measurementId] = false;
    if (started) return;
    started = true;
    gtag('js', new Date());
    const page = new URL(location.href);
    // Query strings can contain customer details. Preserve only campaign attribution.
    for (const key of [...page.searchParams.keys()]) {
      if (!/^utm_(source|medium|campaign|content|term)$/.test(key)) page.searchParams.delete(key);
    }
    page.hash = '';
    gtag('config', measurementId, {page_location: page.href, page_referrer: document.referrer.split('?')[0].split('#')[0], allow_google_signals: false, allow_ad_personalization_signals: false, cookie_expires: 15552000});
    const tag = document.createElement('script');
    tag.async = true;
    tag.src = 'https://www.googletagmanager.com/gtag/js?id=' + measurementId;
    document.head.appendChild(tag);
  }
  function clearAnalyticsCookies() {
    for (const cookie of document.cookie.split(';')) {
      const name = cookie.trim().split('=')[0];
      if (!/^_ga(?:_|$)/.test(name)) continue;
      for (const domain of ['', location.hostname, '.voxdonna.com']) {
        document.cookie = name + '=; Max-Age=0; Path=/; SameSite=Lax' + (domain ? '; Domain=' + domain : '');
      }
    }
  }
  const style = document.createElement('style');
  style.textContent = '#vd-analytics-panel,#vd-analytics-settings{font:14px/1.5 Inter,sans-serif;color:#f5f5f7;background:#0a0a0c;box-sizing:border-box;z-index:10000}#vd-analytics-panel{position:fixed;bottom:64px;left:16px;width:min(440px,calc(100vw - 32px));max-height:calc(100vh - 96px);overflow:auto;border:1px solid #c17f59;border-radius:12px;padding:24px;box-shadow:0 8px 32px #0a0a0c}#vd-analytics-panel[hidden]{display:none}#vd-analytics-panel p{margin:0 0 16px}#vd-analytics-panel a{color:#d4a574}#vd-analytics-panel button,#vd-analytics-settings{cursor:pointer;border:1px solid #c17f59;border-radius:999px;padding:10px 16px;font:inherit}#vd-analytics-panel button{background:#0a0a0c;color:#f5f5f7;margin:4px 8px 0 0}#vd-analytics-panel button:focus-visible,#vd-analytics-settings:focus-visible{outline:2px solid #d4a574;outline-offset:3px}#vd-analytics-settings{position:fixed;bottom:16px;left:16px;font-size:12px}';
  document.head.appendChild(style);
  const panel = document.createElement('section');
  panel.id = 'vd-analytics-panel';
  panel.setAttribute('aria-label', 'Analytics preferences');
  panel.innerHTML = '<p><strong>Your analytics choice.</strong></p><p>With your permission, Google Analytics measures visits and interactions on this website. Analytics stays off until you accept. Change your choice anytime. <a href="/privacy.html#website-analytics">Privacy details</a></p><button type="button" data-choice="granted">Accept analytics</button><button type="button" data-choice="denied">Reject analytics</button>';
  panel.hidden = choice !== null;
  const settings = document.createElement('button');
  settings.id = 'vd-analytics-settings';
  settings.type = 'button';
  settings.textContent = 'Analytics settings';
  settings.setAttribute('aria-controls', panel.id);
  settings.setAttribute('aria-expanded', String(!panel.hidden));
  settings.addEventListener('click', () => {
    panel.hidden = !panel.hidden;
    settings.setAttribute('aria-expanded', String(!panel.hidden));
    if (!panel.hidden) panel.querySelector('button').focus();
  });
  panel.addEventListener('click', event => {
    const value = event.target.dataset.choice;
    if (!['granted', 'denied'].includes(value)) return;
    choice = value;
    try { localStorage.setItem(preferenceKey, JSON.stringify({value, updated: Date.now()})); } catch (_) { /* Apply the choice for this page even without persistence. */ }
    window['ga-disable-' + measurementId] = value !== 'granted';
    gtag('consent', 'update', {analytics_storage: value});
    if (value === 'granted') start(); else clearAnalyticsCookies();
    panel.hidden = true;
    settings.setAttribute('aria-expanded', 'false');
    settings.focus();
  });
  document.body.append(panel, settings);
  if (choice === 'granted') start();
})();
