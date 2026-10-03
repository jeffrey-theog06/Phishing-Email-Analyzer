/* ==========================================================================
   Phishing Email Analyser — js/app.js
   --------------------------------------------------------------------------
   Connects the page controls to the analyser and the renderer. This is the
   only file that touches the page, and it never makes a network request of
   any kind. No analytics, no telemetry, no remote calls.
   ========================================================================== */
(function () {
  'use strict';

  var PEA = window.PEA;
  var refs = {};
  var toastTimer = null;

  /* ----------------------------------------------------------------------
     Alarm preference.
     Kept in memory ONLY. Remembering it in localStorage would contradict the
     promise that this page stores nothing about your session.
     ---------------------------------------------------------------------- */
  var alarmOn = true;

  function prefersReducedMotion() {
    try {
      return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    } catch (e) {
      return false;
    }
  }

  function updateAlarmButton() {
    if (!refs.alarmToggle) { return; }
    refs.alarmToggle.setAttribute('aria-pressed', alarmOn ? 'true' : 'false');
    refs.alarmToggle.textContent = alarmOn ? 'Alarm effects: ON' : 'Alarm effects: OFF';
    refs.alarmToggle.className = 'btn btn--small btn--auto' + (alarmOn ? '' : ' btn--ghost');
  }

  /* ----------------------------------------------------------------------
     Small transient message (used for "copied", "paste a message first", ...)
     ---------------------------------------------------------------------- */
  function toast(message) {
    if (!refs.toast) { return; }
    refs.toast.textContent = message;
    refs.toast.classList.add('is-visible');
    if (toastTimer) { window.clearTimeout(toastTimer); }
    toastTimer = window.setTimeout(function () {
      refs.toast.classList.remove('is-visible');
    }, 2600);
  }

  /* ----------------------------------------------------------------------
     Live "what did we detect" badges under the textarea. This is a cheap
     scan (no scoring) so it can run while the visitor types.
     ---------------------------------------------------------------------- */
  function updateDetectionBadges() {
    var text = refs.input.value;
    clear(refs.detectRow);
    refs.charCount.textContent = text.length.toLocaleString() + ' characters';

    if (!text.trim()) { return; }

    var parsed = PEA.headers.parse(text);
    var body = parsed.found ? parsed.body : text;
    var urlList = PEA.urls.extract(body).urls;
    var files = PEA.rules.extractFilenames(body, []);

    function badge(label, kind) {
      refs.detectRow.appendChild(el('span', 'pill' + (kind ? ' pill--' + kind : ''), label));
    }

    if (parsed.found) { badge('Raw headers detected', 'info'); }
    if (PEA.html.looksLikeHtml(text)) { badge('HTML source detected', 'info'); }
    if (urlList.length) { badge(urlList.length + ' link' + (urlList.length === 1 ? '' : 's') + ' found', 'info'); }
    if (files.length) { badge(files.length + ' possible attachment' + (files.length === 1 ? '' : 's'), 'info'); }
    if (!parsed.found && !PEA.html.looksLikeHtml(text)) {
      badge('Body text only \u2013 pasting raw headers adds more checks');
    }
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text != null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) { node.removeChild(node.firstChild); }
  }

  /* ----------------------------------------------------------------------
     Run the analysis and show the result
     ---------------------------------------------------------------------- */
  function analyseNow() {
    var text = refs.input.value;

    if (!text.trim()) {
      toast('Paste a message first, or choose one of the example emails.');
      refs.input.focus();
      return;
    }

    var started = (window.performance && window.performance.now) ? window.performance.now() : 0;
    var result = PEA.analyser.analyse(text);
    var took = started ? Math.round(window.performance.now() - started) : 0;

    PEA.ui.renderResult(result, refs.results);
    PEA.ui.renderHud(result, refs.hud, took);
    refs.results.setAttribute('aria-busy', 'false');

    if (window.matchMedia && window.matchMedia('(max-width: 1059px)').matches) {
      refs.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    toast('Analysed in ' + took + ' ms: ' + result.band.label + ' (' + result.score + '/100)');
  }

  function loadSample(id) {
    var sample = PEA.samples.byId(id);
    if (!sample) { return; }
    refs.input.value = sample.text;
    updateDetectionBadges();
    analyseNow();
  }

  /* ----------------------------------------------------------------------
     Saving a report. Everything happens locally: the file is assembled in
     memory and handed to the browser's own download prompt. No upload.
     ---------------------------------------------------------------------- */
  function download(filename, text, mime) {
    try {
      var blob = new Blob([text], { type: mime + ';charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
      toast('Report saved to your downloads folder.');
    } catch (e) {
      toast('Your browser blocked the download. You can copy the report instead.');
    }
  }

  function copyText(text, okMessage) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        toast(okMessage);
      })['catch'](function () {
        toast('Copying was blocked by your browser. Please select the text and copy it manually.');
      });
    } else {
      toast('This browser does not allow copying from a local page. Please select the text and copy it manually.');
    }
  }

  function requireResult() {
    var text = refs.input.value;
    if (!text.trim()) {
      toast('Nothing to report yet \u2014 paste a message and analyse it first.');
      return null;
    }
    return PEA.analyser.analyse(text);
  }

  /* ----------------------------------------------------------------------
     Wire everything up once the page is ready
     ---------------------------------------------------------------------- */
  function init() {
    refs.input = document.getElementById('email-input');
    refs.analyseBtn = document.getElementById('analyse-btn');
    refs.clearBtn = document.getElementById('clear-btn');
    refs.pasteBtn = document.getElementById('paste-btn');
    refs.sampleChips = document.getElementById('sample-chips');
    refs.results = document.getElementById('results');
    refs.referenceBody = document.getElementById('reference-body');
    refs.detectRow = document.getElementById('detect-row');
    refs.charCount = document.getElementById('char-count');
    refs.toast = document.getElementById('toast');
    refs.copyBtn = document.getElementById('copy-btn');
    refs.downloadTxtBtn = document.getElementById('download-txt-btn');
    refs.downloadJsonBtn = document.getElementById('download-json-btn');
    refs.printBtn = document.getElementById('print-btn');
    refs.year = document.getElementById('year');
    refs.hud = document.getElementById('hud');
    refs.alarmToggle = document.getElementById('alarm-toggle');
    refs.progress = document.getElementById('scroll-progress');
    refs.announcer = document.getElementById('verdict-announcer');

    if (refs.year) { refs.year.textContent = String(new Date().getFullYear()); }

    // Alarm effects default to ON, unless the operating system is already
    // asking for reduced motion — in which case respect that from the start.
    alarmOn = !prefersReducedMotion();
    PEA.ui.setAlarm(alarmOn);
    updateAlarmButton();
    PEA.ui.renderHud(null, refs.hud);

    // Scroll progress bar. Guarded, so the page still works anywhere that
    // does not support these events.
    if (window.addEventListener) {
      var tick = false;
      var updateProgress = function () {
        tick = false;
        if (!refs.progress) { return; }
        var doc = document.documentElement;
        if (!doc || typeof doc.scrollHeight !== 'number') { return; }
        var max = doc.scrollHeight - doc.clientHeight;
        var top = window.pageYOffset || doc.scrollTop || 0;
        var pct = max > 0 ? Math.min(100, Math.max(0, (top / max) * 100)) : 0;
        refs.progress.style.width = pct + '%';
      };
      window.addEventListener('scroll', function () {
        if (tick) { return; }
        tick = true;
        if (window.requestAnimationFrame) { window.requestAnimationFrame(updateProgress); } else { updateProgress(); }
      }, { passive: true });
      window.addEventListener('resize', updateProgress);
    }

    // One button per built-in example message.
    if (refs.sampleChips) {
      PEA.samples.all.forEach(function (sample) {
        var chip = el('button', 'chip', sample.label);
        chip.type = 'button';
        chip.title = sample.description;
        chip.addEventListener('click', function () { loadSample(sample.id); });
        refs.sampleChips.appendChild(chip);
      });
    }

    PEA.ui.renderEmpty(refs.results);
    PEA.ui.renderReferenceTable(refs.referenceBody);
    updateDetectionBadges();

    refs.analyseBtn.addEventListener('click', analyseNow);

    refs.clearBtn.addEventListener('click', function () {
      refs.input.value = '';
      updateDetectionBadges();
      PEA.ui.renderEmpty(refs.results);
      refs.input.focus();
      toast('Cleared. Nothing was stored anywhere.');
    });

    if (refs.pasteBtn) {
      refs.pasteBtn.addEventListener('click', function () {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
          toast('Your browser will not let a local page read the clipboard. Use Ctrl+V in the box instead.');
          refs.input.focus();
          return;
        }
        navigator.clipboard.readText().then(function (text) {
          if (!text) { toast('The clipboard appears to be empty.'); return; }
          refs.input.value = text;
          updateDetectionBadges();
          toast('Pasted ' + text.length.toLocaleString() + ' characters from the clipboard.');
        })['catch'](function () {
          toast('Clipboard access was refused. Press Ctrl+V in the text box instead.');
        });
      });
    }

    var debounce = null;
    refs.input.addEventListener('input', function () {
      if (debounce) { window.clearTimeout(debounce); }
      debounce = window.setTimeout(updateDetectionBadges, 250);
    });

    refs.input.addEventListener('keydown', function (event) {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        analyseNow();
      }
    });

    if (refs.copyBtn) {
      refs.copyBtn.addEventListener('click', function () {
        var result = requireResult();
        if (result) { copyText(PEA.ui.toPlainText(result), 'Report copied to the clipboard.'); }
      });
    }

    if (refs.downloadTxtBtn) {
      refs.downloadTxtBtn.addEventListener('click', function () {
        var result = requireResult();
        if (result) { download('phishing-analysis-report.txt', PEA.ui.toPlainText(result), 'text/plain'); }
      });
    }

    if (refs.downloadJsonBtn) {
      refs.downloadJsonBtn.addEventListener('click', function () {
        var result = requireResult();
        if (result) { download('phishing-analysis-report.json', PEA.ui.toJson(result), 'application/json'); }
      });
    }

    if (refs.printBtn) {
      refs.printBtn.addEventListener('click', function () { window.print(); });
    }

    if (refs.alarmToggle) {
      refs.alarmToggle.addEventListener('click', function () {
        alarmOn = !alarmOn;
        PEA.ui.setAlarm(alarmOn);
        updateAlarmButton();
        toast(alarmOn
          ? 'Alarm effects on. This preference is not saved \u2014 reloading resets it.'
          : 'Alarm effects off. Colours stay, motion stops.');
      });
    }

    // Keep the panel and theme consistent if the visitor changes their
    // system's reduced-motion setting mid-visit.
    if (window.matchMedia) {
      try {
        var mq = window.matchMedia('(prefers-reduced-motion: reduce)');
        var onMotionChange = function () {
          if (mq.matches) {
            alarmOn = false;
            PEA.ui.setAlarm(false);
            updateAlarmButton();
            toast('Reduced motion detected: alarm effects switched off.');
          }
        };
        if (mq.addEventListener) { mq.addEventListener('change', onMotionChange); }
        else if (mq.addListener) { mq.addListener(onMotionChange); }
      } catch (e) { /* not supported: nothing to do */ }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}());
