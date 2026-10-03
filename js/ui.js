/* ==========================================================================
   Phishing Email Analyser — js/ui.js
   --------------------------------------------------------------------------
   Builds the results view.

   SECURITY NOTE: everything derived from the pasted email is inserted with
   textContent, never with innerHTML. That matters because the visitor may
   paste raw HTML, and a phishing message can contain script tags. Treating
   pasted content as text means nothing from the email can ever run here.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';

  /* ----------------------------------------------------------------------
     Tiny DOM helpers
     ---------------------------------------------------------------------- */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text != null) { node.textContent = String(text); }
    return node;
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS(NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    }
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) { node.removeChild(node.firstChild); }
  }

  function append(node) {
    for (var i = 1; i < arguments.length; i++) {
      var child = arguments[i];
      if (child) { node.appendChild(child); }
    }
    return node;
  }

  /* ----------------------------------------------------------------------
     Highlight the exact words that triggered a rule, inside the surrounding
     sentence, so the reader can see the evidence in context.
     ---------------------------------------------------------------------- */
  function matchNode(snippetText, needle) {
    var div = el('div', 'match');
    var text = String(snippetText == null ? '' : snippetText);
    var want = String(needle == null ? '' : needle);
    var idx = want ? text.toLowerCase().indexOf(want.toLowerCase()) : -1;

    if (idx === -1) {
      div.textContent = text;
      return div;
    }
    div.appendChild(document.createTextNode(text.slice(0, idx)));
    div.appendChild(el('span', 'hl', text.substr(idx, want.length)));
    div.appendChild(document.createTextNode(text.slice(idx + want.length)));
    return div;
  }

  /* ----------------------------------------------------------------------
     Circular score gauge (plain SVG, drawn in the browser)
     ---------------------------------------------------------------------- */
  function buildGauge(score) {
    var R = 54;
    var C = 2 * Math.PI * R;
    var clamped = Math.max(0, Math.min(100, score));

    var wrap = el('div', 'gauge-wrap');
    var svg = svgEl('svg', { viewBox: '0 0 130 130', 'class': 'gauge', role: 'img', 'aria-label': 'Risk score ' + score + ' out of 100' });
    var group = svgEl('g', { transform: 'rotate(-90 65 65)' });

    group.appendChild(svgEl('circle', { cx: 65, cy: 65, r: R, 'class': 'gauge-track' }));

    var value = svgEl('circle', {
      cx: 65, cy: 65, r: R, 'class': 'gauge-value',
      'stroke-dasharray': C.toFixed(2),
      'stroke-dashoffset': (C * (1 - clamped / 100)).toFixed(2)
    });
    group.appendChild(value);
    svg.appendChild(group);

    var center = el('div', 'gauge-center');
    append(center,
      el('span', 'gauge-score', String(score)),
      el('span', 'gauge-outof', 'OUT OF 100')
    );

    append(wrap, svg, center);
    return wrap;
  }

  /* ----------------------------------------------------------------------
     Score hero: gauge, band label, and the headline statistics
     ---------------------------------------------------------------------- */
  function statBox(label, value, tone, suffix) {
    var box = el('div', 'stat' + (tone ? ' stat--' + tone : ''));
    box.appendChild(el('span', 'k', label));
    var v = el('span', 'v', String(value));
    if (suffix) { v.appendChild(el('small', null, ' ' + suffix)); }
    box.appendChild(v);
    return box;
  }

  function buildScoreHero(result) {
    var card = el('section', 'card score-hero tone-' + result.band.tone);

    card.appendChild(buildGauge(result.score));

    var meta = el('div', 'score-meta');

    var badge = el('span', 'band-badge');
    badge.appendChild(el('span', 'dot'));
    badge.appendChild(document.createTextNode(result.band.label));
    meta.appendChild(badge);
    meta.appendChild(el('p', 'lede', result.band.blurb));

    var stats = el('div', 'stat-grid');
    stats.appendChild(statBox('Critical', result.stats.critical, result.stats.critical ? 'high' : 'ok'));
    stats.appendChild(statBox('High', result.stats.high, result.stats.high ? 'high' : 'ok'));
    stats.appendChild(statBox('Medium', result.stats.medium, result.stats.medium ? 'medium' : 'ok'));
    stats.appendChild(statBox('Low', result.stats.low, result.stats.low ? 'low' : 'ok'));
    stats.appendChild(statBox('Links checked', result.detection.urlCount, null));
    stats.appendChild(statBox('Attachments', result.detection.fileCount, null));
    meta.appendChild(stats);

    if (result.detection.countedFindings === 0) {
      meta.appendChild(el('p', 'small faint mt-2',
        'No scoring rule matched. That is not proof the message is safe: it may simply be a type of attack this tool does not look for, or one aimed at something other than money, links or attachments.'));
    }

    card.appendChild(meta);
    return card;
  }

  /* ----------------------------------------------------------------------
     "How this score was built" — the arithmetic, in the open
     ---------------------------------------------------------------------- */
  function buildScoreMath(result) {
    var card = el('section', 'card');
    card.appendChild(el('h3', null, 'How the score of ' + result.score + ' was built'));
    card.appendChild(el('p', 'small muted',
      'Every rule that fired adds a fixed number of points. The totals are added up and capped at 100. Each line below is one rule, and the same rule is listed in the scoring reference further down the page.'));

    var box = el('div', 'score-math');
    var scoring = result.findings.filter(function (f) { return (f.points || 0) > 0; });

    if (!scoring.length) {
      box.appendChild(el('div', 'row', 'No scoring rule matched this message.'));
    } else {
      scoring.forEach(function (f) {
        var row = el('div', 'row');
        row.appendChild(el('span', null, f.title + ' (' + f.id + ')'));
        row.appendChild(el('span', null, '+' + f.points));
        box.appendChild(row);
      });
      var subtotal = el('div', 'row');
      subtotal.appendChild(el('span', null, 'Total before cap'));
      subtotal.appendChild(el('span', null, String(result.rawScore)));
      box.appendChild(subtotal);

      var finalRow = el('div', 'row row--total');
      finalRow.appendChild(el('span', null, result.capped ? 'Final score (capped at 100)' : 'Final score'));
      finalRow.appendChild(el('span', null, String(result.score)));
      box.appendChild(finalRow);

      if (result.capped) {
        box.appendChild(el('div', 'row', 'The uncapped total was ' + result.rawScore + ', which is ' + (result.rawScore - 100) + ' above the maximum. The cap exists so that no single message can produce an unreadable number.'));
      }
    }

    card.appendChild(box);
    return card;
  }

  /* ----------------------------------------------------------------------
     Findings, grouped by category, most serious first
     ---------------------------------------------------------------------- */
  var CATEGORY_ORDER = ['Credentials', 'Pressure tactics', 'Money and payments', 'Impersonation',
    'Links and actions', 'Attachments', 'Message source', 'Email headers', 'Authentication',
    'Combination of findings'];

  function severityTag(sev) {
    return el('span', 'sev sev--' + sev, sev);
  }

  function pointsTag(points) {
    if (!points) { return el('span', 'points points--zero', 'no points'); }
    return el('span', 'points', '+' + points + ' pts');
  }

  function findingNode(f) {
    var node = el('article', 'finding');

    var head = el('div', 'finding-head');
    head.appendChild(el('h4', 'finding-title', f.title));
    var flags = el('div', 'finding-flags');
    flags.appendChild(severityTag(f.severity));
    flags.appendChild(pointsTag(f.points));
    head.appendChild(flags);
    node.appendChild(head);

    node.appendChild(el('p', 'finding-why', f.why));

    if (f.snippets && f.snippets.length) {
      var box = el('div', 'matches');
      f.snippets.forEach(function (s) { box.appendChild(matchNode(s.text, s.match)); });
      node.appendChild(box);
    } else if (f.matches && f.matches.length) {
      var box2 = el('div', 'matches');
      f.matches.forEach(function (m) { box2.appendChild(matchNode(m, null)); });
      node.appendChild(box2);
    }

    if (f.advice) { node.appendChild(el('p', 'finding-advice', f.advice)); }
    return node;
  }

  function buildFindingsSection(result) {
    var card = el('section', 'card');

    var head = el('div', 'card-head');
    var titles = el('div');
    titles.appendChild(el('h3', 'card-title', 'Warning signs found'));
    titles.appendChild(el('p', 'card-sub',
      result.detection.countedFindings + ' scoring finding' + (result.detection.countedFindings === 1 ? '' : 's') +
      ' \u00b7 highest severity first \u00b7 each line shows its own points and the text that triggered it'));
    head.appendChild(titles);
    card.appendChild(head);

    if (!result.findings.length) {
      var ok = el('div', 'callout callout--ok');
      ok.appendChild(el('p', null, 'None of the checks in this tool matched the text you pasted.'));
      ok.appendChild(el('p', null, 'Please read that carefully: it means no warning sign was detectable here, not that the message is genuine. Attackers constantly change wording, and a short message with no links may simply be an attempt at conversation before a later request.'));
      card.appendChild(ok);
      return card;
    }

    var groups = {};
    result.findings.forEach(function (f) {
      if (!groups[f.category]) { groups[f.category] = { items: [], points: 0 }; }
      groups[f.category].items.push(f);
      groups[f.category].points += (f.points || 0);
    });

    Object.keys(groups).sort(function (a, b) {
      var ia = CATEGORY_ORDER.indexOf(a);
      var ib = CATEGORY_ORDER.indexOf(b);
      if (ia === -1) { ia = 99; }
      if (ib === -1) { ib = 99; }
      return ia - ib || a.localeCompare(b);
    }).forEach(function (key) {
      var g = groups[key];
      var wrap = el('div', 'group mt-2');

      var gh = el('div', 'group-head');
      gh.appendChild(el('h3', null, key));
      gh.appendChild(el('span', 'count', g.items.length + (g.items.length === 1 ? ' entry' : ' entries')));
      gh.appendChild(el('span', 'spacer'));
      gh.appendChild(pointsTag(g.points));
      wrap.appendChild(gh);

      g.items.forEach(function (f) { wrap.appendChild(findingNode(f)); });
      card.appendChild(wrap);
    });

    return card;
  }

  /* ----------------------------------------------------------------------
     "What was examined": the raw ingredients behind the result
     ---------------------------------------------------------------------- */
  function buildEvidenceSection(result) {
    var card = el('section', 'card');
    card.appendChild(el('h3', null, 'What was examined'));
    card.appendChild(el('p', 'small muted',
      'These are the raw ingredients the checks worked from. None of the addresses below is a clickable link \u2014 that is deliberate, so no suspect address can be opened by accident.'));

    var grid = el('div', 'artefact-grid mt-2');

    // --- Links ---------------------------------------------------------
    var links = el('div');
    links.appendChild(el('h4', null, 'Links found (' + result.urlDetails.length + ')'));
    if (!result.urlDetails.length) {
      links.appendChild(el('p', 'small faint',
        'No printed links were found in the message. If the message used a button rather than a visible address, paste its raw HTML source to compare the button text with where it really points.'));
    } else {
      result.urlDetails.forEach(function (d) {
        var item = el('div', 'url-item');
        item.appendChild(el('div', 'url-line', d.display));
        item.appendChild(el('div', 'small faint mono',
          'domain: ' + (d.registrable || d.host) + (d.scheme && d.scheme !== '(none)' ? '  \u00b7  ' + d.scheme : '  \u00b7  written without a protocol')));
        var flags = el('div', 'flag-row');
        d.flags.forEach(function (f) {
          var cls = 'flag';
          if (f.tone === 'bad') { cls = 'flag flag--bad'; }
          else if (f.tone === 'warn') { cls = 'flag flag--warn'; }
          else if (f.tone === 'ok') { cls = 'flag flag--ok'; }
          flags.appendChild(el('span', cls, f.label));
        });
        item.appendChild(flags);
        links.appendChild(item);
      });
    }
    grid.appendChild(links);

    // --- Attachments ---------------------------------------------------
    var files = el('div');
    files.appendChild(el('h4', null, 'Possible attachments (' + result.filenames.length + ')'));
    if (!result.filenames.length) {
      files.appendChild(el('p', 'small faint',
        'No filename was found in the text. Attachment names often appear in the message body, for example "please see the attached invoice.pdf".'));
    } else {
      var list = el('div', 'flag-row');
      result.filenames.forEach(function (name) {
        var ext = PEA.rules.extensionOf(name);
        var dangerous = (PEA.lists.ATTACHMENT_EXTENSIONS.executable || []).indexOf(ext) !== -1 ||
          (PEA.lists.ATTACHMENT_EXTENSIONS.diskImage || []).indexOf(ext) !== -1 ||
          (PEA.lists.ATTACHMENT_EXTENSIONS.macroEnabled || []).indexOf(ext) !== -1 ||
          (PEA.lists.ATTACHMENT_EXTENSIONS.archive || []).indexOf(ext) !== -1;
        list.appendChild(el('span', 'flag' + (dangerous ? ' flag--bad' : ''), name));
      });
      files.appendChild(list);
    }
    grid.appendChild(files);

    // --- Headers -------------------------------------------------------
    var headers = el('div');
    headers.appendChild(el('h4', null, 'Sender details'));
    if (!result.headerFound) {
      headers.appendChild(el('p', 'small faint',
        'The pasted text had no raw header block, so the sender, reply-to address and authentication results could not be read. In your mail client choose "View source" or "Show original" and copy everything, including the top lines, to include them.'));
    } else {
      var h = result.header;
      var dl = el('dl', 'kv');
      function pair(key, value) {
        if (!value) { return; }
        dl.appendChild(el('dt', null, key));
        dl.appendChild(el('dd', null, value));
      }
      pair('From', h.fromDisplay ? '"' + h.fromDisplay + '" <' + h.from + '>' : h.from);
      pair('Sender domain', h.fromRegistrable);
      pair('Reply-To', h.replyTo);
      if (h.returnPath) { pair('Return-Path', h.returnPath); }
      pair('Subject', h.subject);
      pair('Date', h.date);
      pair('Received hops', h.receivedCount ? String(h.receivedCount) : '');
      pair('SPF', h.spf || 'not stated in these headers');
      pair('DKIM', h.dkim || 'not stated in these headers');
      pair('DMARC', h.dmarc || 'not stated in these headers');
      headers.appendChild(dl);
    }
    grid.appendChild(headers);

    card.appendChild(grid);
    return card;
  }

  /* ----------------------------------------------------------------------
     Explanatory notes: things worth seeing that carry no points, such as a
     successful SPF check or the absence of authentication results.
     ---------------------------------------------------------------------- */
  function buildNotesSection(result) {
    if (!result.notes || !result.notes.length) { return null; }

    var card = el('section', 'card');
    card.appendChild(el('h3', null, 'Additional context'));
    card.appendChild(el('p', 'small muted',
      'These observations do not add points. They are here so that a "pass" is visible as clearly as a failure, and so you can see when a check could not be performed at all.'));

    result.notes.forEach(function (note) {
      var tone = note.severity === 'ok' ? ' callout--ok' : (note.severity === 'warn' ? ' callout--warn' : ' callout--info');
      var box = el('div', 'callout mt-2' + tone);
      box.appendChild(el('p', null, note.title));
      box.appendChild(el('p', null, note.text));
      card.appendChild(box);
    });

    return card;
  }

  /* ----------------------------------------------------------------------
     Recommendations: numbered, prioritised, plain English
     ---------------------------------------------------------------------- */
  function buildRecommendationsSection(result) {
    var card = el('section', 'card');
    card.appendChild(el('h3', null, 'What to do next'));
    card.appendChild(el('p', 'small muted',
      'In order of importance. Nothing here asks you to open, click or reply to anything in the message.'));

    var list = el('ol', 'rec-list mt-2');
    result.recommendations.forEach(function (rec) {
      var li = el('li');
      var body = el('span');
      body.appendChild(el('strong', null, rec.tag));
      body.appendChild(document.createTextNode(rec.text));
      li.appendChild(body);
      list.appendChild(li);
    });
    card.appendChild(list);
    return card;
  }

  /* ----------------------------------------------------------------------
     The standing reminder. It appears on every result, on purpose.
     ---------------------------------------------------------------------- */
  function buildReminderBanner() {
    var box = el('div', 'callout callout--warn');
    box.appendChild(el('p', null, 'This score describes warning signs, not guilt.'));
    box.appendChild(el('p', null,
      'This is an educational triage tool. It cannot tell you whether an email is malicious or genuine, and a low score is not a guarantee. Always confirm important messages through the organisation\u2019s official app or website, or by calling a number you already have \u2014 never one printed in the message. Do not click links, open attachments or scan QR codes "just to see what happens".'));
    return box;
  }

  /* ----------------------------------------------------------------------
     Public API used by app.js
     ---------------------------------------------------------------------- */
  function renderEmpty(node) {
    if (!node) { return; }
    clear(node);
    resetTheme();
    var box = el('div', 'empty-state');
    box.appendChild(el('h3', null, 'Ready when you are'));
    box.appendChild(el('p', null,
      'Paste the contents of a suspicious email on the left, then select "Analyse Email". For the fullest picture paste the whole raw message (in most mail clients that is "View source" or "Show original"), because that includes the headers, the true link destinations and the names of any attachments.'));
    box.appendChild(el('p', null,
      'Nothing you paste is sent anywhere. This page has no server, no accounts, no cookies and no analytics.'));
    node.appendChild(box);
  }

  function renderResult(result, node) {
    if (!node) { return; }
    clear(node);

    // The whole page takes on the colour of the verdict.
    applyRiskTheme(result);

    var stack = el('div', 'result-stack');
    stack.appendChild(buildReminderBanner());

    var metaLine = el('p', 'small faint',
      'Analysed ' + result.meta.characters.toLocaleString() + ' characters (' + result.meta.words.toLocaleString() +
      ' words), entirely inside your browser. ' +
      (result.detection.headersFound ? 'Raw headers were present. ' : 'No raw headers were present. ') +
      (result.detection.htmlFound ? 'HTML source was detected. ' : ''));
    stack.appendChild(metaLine);

    stack.appendChild(buildConsole(result));
    stack.appendChild(buildScoreHero(result));
    stack.appendChild(buildScoreMath(result));
    stack.appendChild(buildFindingsSection(result));
    stack.appendChild(buildEvidenceSection(result));

    var notes = buildNotesSection(result);
    if (notes) { stack.appendChild(notes); }

    stack.appendChild(buildRecommendationsSection(result));

    var limits = el('div', 'callout callout--info mt-1');
    limits.appendChild(el('p', null, 'What this tool cannot tell you'));
    limits.appendChild(el('p', null,
      'It cannot confirm that a message is malicious, and it cannot confirm that one is genuine. It cannot check whether a domain was registered last week, whether it appears on a blocklist, or where a link would actually lead \u2014 because all of that would require contacting the internet, which this tool deliberately never does. Attachments are judged by their filenames, not their contents. Images, PDF text and QR codes are not read at all.'));
    stack.appendChild(limits);

    node.appendChild(stack);
    node.setAttribute('aria-busy', 'false');
  }

  /* ----------------------------------------------------------------------
     The scoring reference table: every rule and every weight
     ---------------------------------------------------------------------- */
  function renderReferenceTable(tbody) {
    if (!tbody) { return; }
    clear(tbody);

    PEA.analyser.allRuleMetadata().forEach(function (rule) {
      var tr = el('tr');
      tr.appendChild(el('td', 'id-cell', rule.id));
      tr.appendChild(el('td', null, rule.source));
      tr.appendChild(el('td', null, rule.title));
      var sev = el('td');
      sev.appendChild(el('span', 'sev sev--' + rule.severity, rule.severity));
      tr.appendChild(sev);
      tr.appendChild(el('td', 'points-cell', rule.points ? '+' + rule.points : '0'));
      tbody.appendChild(tr);
    });
  }

  /* ----------------------------------------------------------------------
     Reports, assembled locally and handed to the browser's download prompt
     ---------------------------------------------------------------------- */
  function toPlainText(result) {
    var lines = [];
    lines.push('PHISHING EMAIL ANALYSER \u2013 EDUCATIONAL TRIAGE REPORT');
    lines.push('Generated locally in the browser. Nothing was uploaded anywhere.');
    lines.push('This report describes warning signs. It is not a verdict on the message.');
    lines.push('');
    lines.push('RISK SCORE: ' + result.score + '/100  (' + result.band.label + ')');
    lines.push('  ' + result.band.blurb);
    lines.push('  Total points before the cap of 100: ' + result.rawScore + (result.capped ? ' (capped)' : ''));
    lines.push('');
    lines.push('WHAT WAS EXAMINED');
    lines.push('  Characters: ' + result.meta.characters);
    lines.push('  Raw headers present: ' + (result.detection.headersFound ? 'yes' : 'no'));
    lines.push('  HTML source detected: ' + (result.detection.htmlFound ? 'yes' : 'no'));
    lines.push('  Links found: ' + result.detection.urlCount);
    lines.push('  Possible attachments: ' + result.detection.fileCount);
    lines.push('');

    if (result.headerFound && result.header) {
      lines.push('SENDER DETAILS');
      lines.push('  From: ' + (result.header.fromDisplay ? '"' + result.header.fromDisplay + '" <' + result.header.from + '>' : result.header.from));
      if (result.header.replyTo) { lines.push('  Reply-To: ' + result.header.replyTo); }
      if (result.header.returnPath) { lines.push('  Return-Path: ' + result.header.returnPath); }
      if (result.header.subject) { lines.push('  Subject: ' + result.header.subject); }
      lines.push('  SPF: ' + (result.header.spf || 'not stated') +
        '   DKIM: ' + (result.header.dkim || 'not stated') +
        '   DMARC: ' + (result.header.dmarc || 'not stated'));
      lines.push('');
    }

    lines.push('WARNING SIGNS (' + result.findings.length + ')');
    if (!result.findings.length) {
      lines.push('  No rule matched. This is not a guarantee that the message is genuine.');
    }
    result.findings.forEach(function (f) {
      lines.push('  [' + (f.points ? '+' + f.points + ' pts' : 'no points') + '] ' + f.title);
      lines.push('      id: ' + f.id + '   severity: ' + f.severity + '   category: ' + f.category);
      lines.push('      why it matters: ' + f.why);
      if (f.snippets && f.snippets.length) {
        f.snippets.forEach(function (s) { lines.push('      evidence: ...' + s.text + '...'); });
      } else if (f.matches && f.matches.length) {
        f.matches.forEach(function (m) { lines.push('      evidence: ' + m); });
      }
      if (f.advice) { lines.push('      what to do: ' + f.advice); }
      lines.push('');
    });

    if (result.notes && result.notes.length) {
      lines.push('ADDITIONAL CONTEXT (no points)');
      result.notes.forEach(function (n) { lines.push('  - ' + n.title + ': ' + n.text); });
      lines.push('');
    }

    lines.push('WHAT TO DO NEXT');
    result.recommendations.forEach(function (rec, i) {
      lines.push('  ' + (i + 1) + '. [' + rec.tag + '] ' + rec.text);
    });
    lines.push('');
    lines.push('LIMITS OF THIS TOOL');
    lines.push('  Analysis happens entirely in the browser and never contacts the internet,');
    lines.push('  so no domain reputation, blocklist or destination check was performed.');
    lines.push('  Attachments are judged by filename only, not by their contents.');
    lines.push('  A low score is not proof that a message is safe.');
    lines.push('');
    return lines.join('\n');
  }

  function toJson(result) {
    var payload = {
      tool: 'Phishing Email Analyser',
      note: 'Educational triage output. Not a verdict. Generated locally in the browser; nothing was uploaded.',
      generatedAt: new Date().toISOString(),
      score: result.score,
      rawScore: result.rawScore,
      capped: result.capped,
      band: { id: result.band.id, label: result.band.label, min: result.band.min, max: result.band.max },
      detection: result.detection,
      meta: { characters: result.meta.characters, words: result.meta.words, truncated: result.meta.truncated },
      sender: result.header || null,
      authentication: result.auth || null,
      findings: result.findings.map(function (f) {
        return {
          id: f.id,
          category: f.category,
          severity: f.severity,
          points: f.points,
          title: f.title,
          why: f.why,
          advice: f.advice,
          evidence: f.snippets ? f.snippets.map(function (s) { return s.text; }) : (f.matches || [])
        };
      }),
      links: result.urlDetails.map(function (d) {
        return {
          address: d.display,
          host: d.host,
          registrableDomain: d.registrable,
          flags: d.flags.map(function (f) { return f.label; })
        };
      }),
      attachments: result.filenames,
      notes: result.notes,
      recommendations: result.recommendations
    };
    return JSON.stringify(payload, null, 2);
  }

  /* ----------------------------------------------------------------------
     RISK THEME
     ----------------------------------------------------------------------
     The verdict drives the colour of the entire page. We do this by setting a
     single data attribute on the <html> element; CSS variables do the rest.

     Note what is deliberately NOT here: no audio, no strobe, no pop-up, and
     no localStorage (remembering a setting would contradict the "nothing is
     stored" promise). The alarm preference lives in memory for this visit
     only.
     ---------------------------------------------------------------------- */
  function applyRiskTheme(result) {
    var root = document.documentElement;
    var risk = result && result.band ? result.band.id : 'none';

    root.setAttribute('data-risk', risk);
    if (result && result.band) {
      root.setAttribute('data-verdict', result.band.label);
    } else {
      root.removeAttribute('data-verdict');
    }

    if (result && !result.meta.empty) {
      document.body.classList.add('has-result');
    } else {
      document.body.classList.remove('has-result');
    }

    // A short, polite announcement for screen readers. The colour and motion
    // are decoration; this is the part that actually informs.
    var live = document.getElementById('verdict-announcer');
    if (live && result && result.band) {
      live.textContent = 'Analysis complete. Risk score ' + result.score + ' out of 100. Verdict: ' +
        result.band.label + '. ' + result.detection.countedFindings + ' warning sign' +
        (result.detection.countedFindings === 1 ? '' : 's') + ' found.';
    } else if (live) {
      live.textContent = '';
    }
  }

  function setAlarm(on) {
    document.documentElement.setAttribute('data-alarm', on ? 'on' : 'off');
  }

  function resetTheme() {
    applyRiskTheme(null);
  }

  /* ----------------------------------------------------------------------
     STATUS BAR (HUD)
     Filled in after every analysis, and reset to "standing by" on clear.
     ---------------------------------------------------------------------- */
  function renderHud(result, node, elapsedMs) {
    if (!node) { return; }
    clear(node);

    node.appendChild(el('span', 'hud-label', 'Local session'));
    node.appendChild(el('span', 'hud-label', '::'));

    if (!result || result.meta.empty) {
      node.appendChild(el('span', 'hud-value', 'standing by'));
      node.appendChild(el('span', 'hud-metric', 'awaiting a message to analyse'));
      return;
    }

    var verdict = el('span', 'hud-value caret');
    verdict.appendChild(el('span', 'typed', result.band.label));
    node.appendChild(verdict);

    node.appendChild(el('span', 'hud-metric', 'score ' + result.score + '/100'));
    node.appendChild(el('span', 'hud-metric', 'signals ' + result.detection.countedFindings));

    if (result.detection.urlCount) {
      node.appendChild(el('span', 'hud-metric', 'links ' + result.detection.urlCount));
    }
    if (result.detection.fileCount) {
      node.appendChild(el('span', 'hud-metric', 'attachments ' + result.detection.fileCount));
    }
    if (result.detection.headersFound) {
      node.appendChild(el('span', 'hud-metric', 'headers parsed'));
    }

    var spacer = el('span', 'hud-spacer');
    node.appendChild(spacer);
    node.appendChild(el('span', 'hud-metric',
      'no network requests \u00b7' + (elapsedMs ? ' analysed in ' + elapsedMs + ' ms \u00b7' : '') + ' nothing stored'));
  }

  /* ----------------------------------------------------------------------
     TERMINAL CONSOLE BLOCK
     A deliberately "analyst console" view of the same result: the pipeline
     stages, then one line per rule that fired, then the arithmetic.
     ---------------------------------------------------------------------- */
  function consoleLines(result) {
    var lines = [];
    var high = result.band.id === 'high';

    lines.push({ text: '$ pea --analyse --local --no-network', cls: '' });
    lines.push({ text: '[i] input .......... ' + result.meta.characters.toLocaleString() + ' characters, ' + result.meta.words.toLocaleString() + ' words' + (result.meta.truncated ? ' (truncated)' : ''), cls: '' });
    lines.push({
      text: result.detection.headersFound
        ? '[+] headers ........ parsed (sender, reply-to, authentication results)'
        : '[-] headers ........ none found \u2014 paste the raw message to enable SPF/DKIM/DMARC checks',
      cls: result.detection.headersFound ? '' : 'console-line--alert'
    });
    lines.push({ text: '[i] links .......... ' + result.detection.urlCount + ' examined as text (never opened)', cls: '' });
    lines.push({ text: '[i] attachments .... ' + result.detection.fileCount + ' filename(s) classified', cls: '' });
    lines.push({ text: result.detection.htmlFound ? '[+] html source .... scanned' : '[-] html source .... not present (plain text only)', cls: '' });

    var scoring = result.findings.filter(function (f) { return (f.points || 0) > 0; });
    lines.push({ text: '', cls: '' });
    if (!scoring.length) {
      lines.push({ text: '[=] no scoring rule matched', cls: '' });
    } else {
      scoring.forEach(function (f) {
        lines.push({
          text: '[!] rule ' + padRight(f.id, 30) + '+' + padLeft(String(f.points), 3) + '  ' + f.title,
          cls: 'console-line--alert'
        });
      });
    }

    lines.push({ text: '', cls: '' });
    lines.push({ text: '[=] subtotal ...... ' + result.rawScore + (result.capped ? ' (above the cap of 100)' : ''), cls: '' });
    lines.push({ text: '[=] score ......... ' + result.score + '/100', cls: '' });
    lines.push({ text: '[#] verdict ....... ' + result.band.label.toUpperCase(), cls: high ? 'console-line--alert' : '' });
    lines.push({ text: '[*] policy ........ warning signs only \u00b7 not a verdict on the sender', cls: '' });
    return lines;
  }

  function padRight(s, n) {
    s = String(s);
    while (s.length < n) { s += '.'; }
    return s;
  }

  function padLeft(s, n) {
    s = String(s);
    while (s.length < n) { s = ' ' + s; }
    return s;
  }

  function buildConsole(result) {
    var box = el('div', 'console');

    var bar = el('div', 'console-bar');
    bar.appendChild(el('span', 'dot'));
    bar.appendChild(document.createTextNode('analysis console \u00b7 runs in this browser tab \u00b7 zero network requests'));
    box.appendChild(bar);

    var body = el('pre', 'console-body');
    consoleLines(result).forEach(function (line, index) {
      var row = el('span', 'console-line' + (line.cls ? ' ' + line.cls : ''), line.text || ' ');
      // Staggered reveal: the lines appear one after another, like output
      // printing to a terminal. Pure CSS delay, so no timers are involved.
      row.style.animationDelay = (index * 55) + 'ms';
      body.appendChild(row);
    });
    box.appendChild(body);
    return box;
  }

  PEA.ui = {
    el: el,
    clear: clear,
    renderEmpty: renderEmpty,
    renderResult: renderResult,
    renderHud: renderHud,
    applyRiskTheme: applyRiskTheme,
    setAlarm: setAlarm,
    resetTheme: resetTheme,
    renderReferenceTable: renderReferenceTable,
    toPlainText: toPlainText,
    toJson: toJson,
    buildGauge: buildGauge,
    consoleLines: consoleLines
  };

}(window.PEA = window.PEA || {}));
