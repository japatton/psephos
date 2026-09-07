/*
  The sign-in splash: ψῆφος becoming PSEPHOS.

  Plays once, on the first load of the shell after login.html redirects here,
  and never on a reload. login.html leaves a sessionStorage flag; this consumes
  it before anything else can. Anyone who has seen it a hundred times sees it
  only on the hundred-and-first sign-in.

  A classic script in <head>, not a module in app.js. A deferred module runs
  after the parser has finished, and the browser is free to paint before that:
  the topbar and "Loading store…" would flash for a frame and then be covered,
  which reads as a glitch. Stamping <html> from here means the first paint is
  already the splash.

  The CSS owns the timeline. This file measures the word, starts the letter
  stage, and enforces the cap and the skip. The overlay fades itself out on a
  fixed delay with a forwards fill, so if anything below throws after the
  overlay is shown the app still surfaces — a stuck overlay is the one outcome
  that must not happen.
*/
(() => {
  'use strict';

  const KEY = 'psephos.splash';
  let armed = false;
  // Private windows can throw on storage access; that is not worth a splash.
  try { armed = sessionStorage.getItem(KEY) === '1'; sessionStorage.removeItem(KEY); } catch { return; }
  if (!armed) return;

  const html = document.documentElement;
  // Reduced motion shows the finished wordmark, still, and then cuts to the
  // app. Not a shorter version of the same thing.
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const CAP = still ? 900 : 2100;

  let done = false;
  const end = () => {
    if (done) return;
    done = true;
    html.classList.remove('splashing');
    removeEventListener('pointerdown', skip, true);
    removeEventListener('keydown', skip, true);
  };
  const skip = () => {
    const el = document.getElementById('splash');
    if (!el || done) return end();
    el.classList.add('out');
    setTimeout(end, 220);
  };

  html.classList.add('splashing');
  setTimeout(end, CAP);
  // Capture on window: the overlay lets pointer events through so the app is
  // usable beneath it, and this sees the click before the app does without
  // taking it away.
  addEventListener('pointerdown', skip, true);
  addEventListener('keydown', skip, true);

  /*
    Each cell animates from the width of its Greek glyph to the width of its
    Latin transliteration, so the word grows from the middle as it changes
    rather than jumping. CSS cannot animate to an auto width, so both are
    measured here and handed over as custom properties. The Latin gradient is
    one gradient sized to the finished word and offset per cell, so it runs
    cyan-to-magenta across PSEPHOS as it does in the masthead rather than
    restarting at every letter.
  */
  const go = () => {
    const el = document.getElementById('splash');
    if (!el || still) return;
    try {
      const word = el.querySelector('.splash-word');
      const units = [...word.querySelectorAll('.u')];
      const latin = units.map(u => u.querySelector('b').getBoundingClientRect().width);
      word.style.setProperty('--W', `${latin.reduce((a, b) => a + b, 0)}px`);
      let x = 0;
      units.forEach((u, k) => {
        u.style.setProperty('--i', String(k));
        u.style.setProperty('--gw', `${u.getBoundingClientRect().width}px`);
        u.style.setProperty('--lw', `${latin[k]}px`);
        u.style.setProperty('--x', `${x}px`);
        x += latin[k];
      });
      el.classList.add('go');
    } catch (err) {
      end();
      throw err;
    }
  };

  // 'interactive' is enough: the overlay is parsed, and DOMContentLoaded would
  // additionally wait for d3 and app.js to execute.
  if (document.readyState !== 'loading') go();
  else document.addEventListener('readystatechange', go, { once: true });
})();
