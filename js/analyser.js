/* ==========================================================================
   Phishing Email Analyser — js/analyser.js
   --------------------------------------------------------------------------
   The scoring engine. It ties the other modules together and produces one
   result object for the interface to render.

   THE SCORING MODEL, IN PLAIN ENGLISH
   -----------------------------------
   1. Every detection rule that fires contributes its own fixed number of
      points. Those numbers are decided in js/rules.js, js/urls.js, js/html.js
      and js/headers.js, and they are shown to the user in a table.
   2. Points are added up and the total is capped at 100.
   3. A few "combination" rules add extra points when two dangerous things
      appear together (for example a password request plus a link to a domain
      the brand does not own). Each combination appears in the results as its
      own visible line, so the total is always fully accounted for.
   4. The total maps to a band:
        0        No obvious warning signs
        1 - 24   Low Risk
        25 - 54  Suspicious
        55 - 100 High Risk

   There is no machine learning, no randomness and no hidden weighting. The
   same pasted text always produces the same score, and every point can be
   traced to a rule the reader can inspect.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var U = PEA.util;
  var MAX_SCORE = 100;

  var BANDS = [
    {
      id: 'clear', min: 0, max: 0, label: 'No Obvious Warning Signs', tone: 'clear',
      blurb: 'None of the checks in this tool found a warning sign in the text you pasted. This is not a statement that the message is genuine; it means nothing obvious was detectable here.'
    },
    {
      id: 'low', min: 1, max: 24, label: 'Low Risk', tone: 'low',
      blurb: 'A small number of weak warning signs were found. They may be completely innocent, but a quick moment of verification is worthwhile.'
    },
    {
      id: 'medium', min: 25, max: 54, label: 'Suspicious', tone: 'medium',
      blurb: 'Several warning signs were found, or one significant one. Treat the message as unverified and confirm it through a channel you trust before acting.'
    },
    {
      id: 'high', min: 55, max: 100, label: 'High Risk', tone: 'high',
      blurb: 'This message shows the pattern of a phishing or social-engineering attempt. Do not act on anything in it. Report it and verify independently.'
    }
  ];

  function bandFor(score) {
    for (var i = 0; i < BANDS.length; i++) {
      if (score >= BANDS[i].min && score <= BANDS[i].max) { return BANDS[i]; }
    }
    return BANDS[BANDS.length - 1];
  }

  /* ----------------------------------------------------------------------
     Run the body-language rules and capture the exact text that triggered
     each one, so the user can see the evidence rather than trusting a number.
     ---------------------------------------------------------------------- */
  function runBodyRules(text, rules) {
    var findings = [];

    rules.forEach(function (rule) {
      var snippets = [];
      rule.patterns.forEach(function (re) {
        var m;
        try { m = re.exec(text); } catch (e) { m = null; }
        if (!m) { return; }
        var start = Math.max(0, m.index - 45);
        var end = Math.min(text.length, m.index + m[0].length + 45);
        snippets.push({
          text: text.slice(start, end).replace(/\s+/g, ' ').trim(),
          match: m[0]
        });
      });
      if (snippets.length) {
        findings.push({
          id: rule.id,
          source: 'body',
          category: rule.category,
          severity: rule.severity,
          points: rule.points,
          title: rule.title,
          why: rule.why,
          advice: rule.advice,
          snippets: snippets.slice(0, 3),
          matches: snippets.map(function (s) { return s.text; }).slice(0, 3)
        });
      }
    });

    return findings;
  }

  /* ----------------------------------------------------------------------
     Combination rules. Two individually moderate findings can add up to
     something far more dangerous, so these add extra points and are shown
     to the user like any other finding.
     ---------------------------------------------------------------------- */
  var COMBINATIONS = [
    {
      id: 'combo_credential_link',
      points: 18,
      severity: 'critical',
      title: 'Asks for credentials AND links to a domain that is not the brand\u2019s',
      why: 'Each of these is a warning on its own. Together they are the standard shape of a credential-phishing attack: a reason to log in, and a fake page to log in to.',
      advice: 'Treat this message as a phishing attempt. Do not follow the link, and report it to your IT or security team.',
      test: function (o) {
        var creds = o.hasAny(['password_request', 'mfa_code_request', 'credential_harvesting', 'embedded_login_form']);
        var badLink = o.hasAny(['brand_lookalike_domain', 'typosquat_domain', 'homoglyph_domain',
          'ip_address_url', 'shortened_url', 'at_sign_in_url', 'misleading_link_text']);
        return creds && badLink;
      },
      evidence: function (o) { return o.urlHosts.slice(0, 2); }
    },
    {
      id: 'combo_pressure_credentials',
      points: 10,
      severity: 'high',
      title: 'Pressure tactics AND a credential request',
      why: 'Urgency or a threat is used to stop you thinking, while the credential request is the goal. This pairing is the most common phishing pattern of all.',
      advice: 'Slow down deliberately. Nothing genuine requires you to hand over login details under time pressure.',
      test: function (o) {
        var creds = o.hasAny(['password_request', 'mfa_code_request', 'credential_harvesting']);
        var pressure = o.hasAny(['urgency_pressure', 'account_threat', 'threat_of_financial_loss', 'security_alert_language']);
        return creds && pressure;
      }
    },
    {
      id: 'combo_payment_authority',
      points: 10,
      severity: 'high',
      title: 'Payment request AND impersonation of authority',
      why: 'This is the classic business email compromise: someone senior-sounding or official-sounding asks for money or for a change of bank details.',
      advice: 'Confirm the request in person or on a number you already have before any money moves.',
      test: function (o) {
        var money = o.hasAny(['unusual_payment', 'bank_details_change', 'unexpected_invoice']);
        var authority = o.hasAny(['bec_authority', 'generic_impersonation', 'display_name_spoof', 'free_mail_sender']);
        return money && authority;
      }
    },
    {
      id: 'combo_attachment_macro',
      points: 10,
      severity: 'high',
      title: 'Risky attachment AND a request to enable content',
      why: 'A document that needs macros enabled, combined with a message telling you to enable them, is the standard delivery method for document-based malware.',
      advice: 'Do not open the attachment and do not enable content. Report the message.',
      test: function (o) {
        var file = o.hasAny(['executable_attachment', 'macro_attachment', 'disk_image_attachment',
          'double_extension', 'archive_attachment', 'risky_attachment']);
        return file && o.hasAny(['macro_request']);
      }
    },
    {
      id: 'combo_auth_identity',
      points: 8,
      severity: 'high',
      title: 'Email authentication failed AND the sender identity does not add up',
      why: 'The technical checks failed and the claimed identity is inconsistent. When both happen together, the message almost certainly was not sent by who it claims to be.',
      advice: 'Do not trust the sender. Report the message and verify any request independently.',
      test: function (o) {
        var authFail = o.hasAny(['spf_fail', 'dkim_fail', 'dmarc_fail']);
        var identity = o.hasAny(['reply_to_mismatch', 'display_name_spoof', 'return_path_mismatch',
          'free_mail_sender', 'message_id_mismatch']);
        return authFail && identity;
      }
    }
  ];

  /* ----------------------------------------------------------------------
     analyse(text, options) -> the complete result object.

     Nothing in here reads or writes the network, the disk, cookies or
     storage. The same input always produces the same output.
     ---------------------------------------------------------------------- */
  function analyse(text, options) {
    var raw = String(text == null ? '' : text);

    // Guard against enormous pastes so the page cannot freeze. 300,000
    // characters is far more than any real email.
    var LIMIT = 300000;
    var truncated = raw.length > LIMIT;
    var input = truncated ? raw.slice(0, LIMIT) : raw;

    // 1. Headers: only used if the text really does begin with a header block.
    var headerResult = PEA.headers.analyse(input);
    var body = headerResult.found ? headerResult.parsed.body : input;

    // 2. Links, extracted from the message body only.
    var urlExtract = PEA.urls.extract(body);
    var urlResult = PEA.urls.analyse(urlExtract.urls);

    // 3. Attachment filenames. URL text is excluded so that domains are not
    //    mistaken for files.
    var filenames = PEA.rules.extractFilenames(body, urlExtract.spans);
    var attachResult = PEA.rules.analyseAttachments(filenames);

    // 4. Language patterns in the body text.
    var bodyFindings = runBodyRules(body, PEA.rules.BODY_RULES);

    // 5. Raw HTML source, if what was pasted is HTML rather than plain text.
    var htmlResult = PEA.html.analyseHtml(input);

    var findings = []
      .concat(bodyFindings, urlResult.findings, attachResult.findings, htmlResult.findings, headerResult.findings);

    // 6. Combination rules, evaluated against everything found so far.
    var idMap = {};
    findings.forEach(function (f) { idMap[f.id] = true; });
    var hosts = [];
    urlResult.details.forEach(function (d) {
      if (d.host && hosts.indexOf(d.host) === -1) { hosts.push(d.host); }
    });
    var ctx = {
      ids: Object.keys(idMap),
      urlHosts: hosts,
      hasAny: function (list) {
        return list.some(function (id) { return idMap[id]; });
      }
    };
    COMBINATIONS.forEach(function (c) {
      if (!c.test(ctx)) { return; }
      findings.push({
        id: c.id,
        source: 'combination',
        category: 'Combination of findings',
        severity: c.severity,
        points: c.points,
        title: c.title,
        why: c.why,
        advice: c.advice,
        matches: c.evidence ? c.evidence(ctx) : []
      });
    });

    // 7. Score: plain addition, then a hard cap at 100.
    var rawScore = findings.reduce(function (sum, f) { return sum + (f.points || 0); }, 0);
    var score = Math.min(MAX_SCORE, rawScore);
    var band = bandFor(score);

    var stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0, counted: 0 };
    findings.forEach(function (f) {
      stats[f.severity] = (stats[f.severity] || 0) + 1;
      if (f.points > 0) { stats.counted++; }
    });

    var result = {
      score: score,
      rawScore: rawScore,
      capped: rawScore > MAX_SCORE,
      band: band,
      findings: sortFindings(findings),
      notes: headerResult.notes || [],
      recommendations: [],
      stats: stats,
      urlDetails: urlResult.details,
      filenames: filenames,
      header: headerResult.summary,
      headerFound: headerResult.found,
      auth: headerResult.auth,
      isHtml: htmlResult.isHtml,
      htmlAnchorCount: htmlResult.anchorCount || 0,
      remoteHosts: htmlResult.remoteHosts || [],
      detection: {
        headersFound: headerResult.found,
        htmlFound: htmlResult.isHtml,
        urlCount: urlResult.details.length,
        fileCount: filenames.length,
        countedFindings: stats.counted
      },
      meta: {
        characters: raw.length,
        words: body.split(/\s+/).filter(Boolean).length,
        truncated: truncated,
        maxScore: MAX_SCORE,
        empty: raw.trim().length === 0
      }
    };

    result.recommendations = PEA.recommendations.build(result);
    return result;
  }

  /* ----------------------------------------------------------------------
     Display order: most serious first, then most points.
     ---------------------------------------------------------------------- */
  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function sortFindings(findings) {
    return findings.slice().sort(function (a, b) {
      var s = (SEVERITY_ORDER[a.severity] || 9) - (SEVERITY_ORDER[b.severity] || 9);
      if (s !== 0) { return s; }
      return (b.points || 0) - (a.points || 0);
    });
  }

  /* ----------------------------------------------------------------------
     Every rule and every weight, for the "scoring reference" table in the
     interface. Nothing is hidden from the reader.
     ---------------------------------------------------------------------- */
  function allRuleMetadata() {
    var out = [];

    PEA.rules.BODY_RULES.forEach(function (r) {
      out.push({ id: r.id, source: 'Message text', category: r.category, title: r.title, severity: r.severity, points: r.points });
    });
    Object.keys(PEA.urls.weights).forEach(function (k) {
      var w = PEA.urls.weights[k];
      out.push({ id: k, source: 'Links', category: 'Links and actions', title: w.title, severity: w.severity, points: w.points });
    });
    Object.keys(PEA.rules.attachmentRules).forEach(function (k) {
      var w = PEA.rules.attachmentRules[k];
      out.push({ id: k, source: 'Attachments', category: w.category, title: w.title, severity: w.severity, points: w.points });
    });
    Object.keys(PEA.html.weights).forEach(function (k) {
      var w = PEA.html.weights[k];
      out.push({ id: k, source: 'HTML source', category: w.category, title: w.title, severity: w.severity, points: w.points });
    });
    Object.keys(PEA.headers.weights).forEach(function (k) {
      var w = PEA.headers.weights[k];
      out.push({ id: k, source: 'Headers', category: w.category, title: w.title, severity: w.severity, points: w.points });
    });
    COMBINATIONS.forEach(function (c) {
      out.push({ id: c.id, source: 'Combination', category: 'Combination of findings', title: c.title, severity: c.severity, points: c.points });
    });

    out.sort(function (a, b) {
      if (b.points !== a.points) { return b.points - a.points; }
      return a.title.localeCompare(b.title);
    });
    return out;
  }

  PEA.analyser = {
    analyse: analyse,
    BANDS: BANDS,
    bandFor: bandFor,
    COMBINATIONS: COMBINATIONS,
    MAX_SCORE: MAX_SCORE,
    sortFindings: sortFindings,
    allRuleMetadata: allRuleMetadata,
    SEVERITY_ORDER: SEVERITY_ORDER
  };
}(window.PEA = window.PEA || {}));



