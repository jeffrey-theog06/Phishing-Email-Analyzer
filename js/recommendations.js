/* ==========================================================================
   Phishing Email Analyser — js/recommendations.js
   --------------------------------------------------------------------------
   Turns the list of findings into a short, prioritised, plain-English action
   list. The advice is written to be safe: it never suggests testing a link,
   opening an attachment or replying, and it always pushes the reader towards
   independent verification through a channel they already trust.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var CORE = {
    neverTest: {
      tag: 'Do not',
      text: 'Do not click any link, open any attachment, scan any QR code or reply to this message to find out what it does. Opening it is exactly what the sender wants.'
    },
    verify: {
      tag: 'Verify',
      text: 'Verify the message independently: open the organisation\u2019s official app or type its website address yourself, or call a number you already have (never one printed in the message).'
    },
    report: {
      tag: 'Report',
      text: 'Report the message to your IT or security team, or to the organisation it pretends to come from, and then delete it or mark it as spam.'
    },
    actedNow: {
      tag: 'Act now',
      text: 'If you already entered details, approved a sign-in, paid money or opened an attachment: change that password immediately, turn on multi-factor authentication, and contact your bank or IT team today. Do not feel embarrassed \u2014 speed is what matters.'
    },
    bankCall: {
      tag: 'Act now',
      text: 'If this involves a change of bank details or a payment, telephone the supplier or colleague on a number you already have to confirm it, and ask your finance team to hold the payment until it is verified.'
    },
    macroCare: {
      tag: 'Never',
      text: 'Never click "Enable Content" or "Enable Editing" on a document that arrived by email. Ask the sender to share it through a normal business system instead.'
    },
    quiet: {
      tag: 'Note',
      text: 'Quiet inboxes are not safe inboxes: this message shows no obvious warning signs, which is not the same as being genuine. Trust your expectations of the sender first.'
    },
    keepEvidence: {
      tag: 'Keep',
      text: 'Keep a copy of the message and its headers if your team asks for them. Your pasted text never leaves this page, so the original in your mailbox is the best evidence.'
    }
  };

  var SOURCE_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function build(result) {
    var recs = [];
    var seen = {};
    var band = result && result.band ? result.band.id : 'low';
    var findings = (result && result.findings) ? result.findings.slice() : [];

    function push(item) {
      var key = String(item.text || '').toLowerCase().slice(0, 90);
      if (seen[key]) { return; }
      seen[key] = true;
      recs.push(item);
    }

    // 1. The most important, always-on advice first.
    push(CORE.neverTest);

    if (band === 'high' || band === 'critical') {
      push(CORE.actedNow);
    }

    // 2. Advice attached to individual findings, most serious first.
    findings
      .slice()
      .sort(function (a, b) {
        var s = (SOURCE_ORDER[a.severity] || 9) - (SOURCE_ORDER[b.severity] || 9);
        return s !== 0 ? s : (b.points || 0) - (a.points || 0);
      })
      .forEach(function (f) {
        if (f.advice && f.points > 0) { push({ tag: 'About this finding', text: f.advice }); }
      });

    // 3. Always-on verification and reporting advice.
    push(CORE.verify);
    push(CORE.report);

    if (recs.some(function (r) { return /bank details|payment/i.test(r.text); })) {
      push(CORE.bankCall);
    }
    if (recs.some(function (r) { return /macro/i.test(r.text); })) {
      push(CORE.macroCare);
    }
    if (!findings.some(function (f) { return f.points > 0; })) {
      push(CORE.quiet);
    }
    push(CORE.keepEvidence);

    // Keep the list readable: eight items is plenty for a triage result.
    return recs.slice(0, 8);
  }

  PEA.recommendations = { build: build, CORE: CORE };
}(window.PEA = window.PEA || {}));
