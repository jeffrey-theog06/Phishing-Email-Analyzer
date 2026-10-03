/* ==========================================================================
   Phishing Email Analyser — js/html.js
   --------------------------------------------------------------------------
   If the visitor pastes the message's raw HTML source (many mail clients have
   a "View source" or "Show original" option) we can look at things plain text
   cannot show: hidden text, fake login forms, tracking pixels, and links whose
   visible text disagrees with where they actually point.

   PRIVACY NOTE: not one byte of this is fetched. Images and links are read as
   text and never loaded, so a tracking pixel in the pasted source is reported
   but never triggered. That is a deliberate design choice.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var U = PEA.util;
  var L = PEA.lists;

  // Rough test for "this looks like HTML source rather than plain text".
  function looksLikeHtml(text) {
    var s = String(text || '');
    var tags = s.match(/<\s*\/?\s*(?:html|head|body|table|tr|td|div|span|p|a|img|font|br|meta|style|form|input)\b[^>]*>/gi) || [];
    return tags.length >= 3;
  }

  function stripTags(s) {
    return String(s || '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
      .replace(/\s+/g, ' ').trim();
  }

  var ALL_TLDS = PEA.urls.COMMON_TLDS.concat(L.SUSPICIOUS_TLDS)
    .filter(function (v, i, a) { return a.indexOf(v) === i; }).join('|');

  var HOSTISH_RE = new RegExp(
    '(?:https?:\\/\\/)?(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\\.)+(?:' + ALL_TLDS + ')\\b', 'gi'
  );

  function domainInText(s) {
    HOSTISH_RE.lastIndex = 0;
    var m = HOSTISH_RE.exec(String(s || ''));
    if (!m) { return ''; }
    return m[0].replace(/^https?:\/\//i, '').replace(/^www\./i, '').split(/[\/?#]/)[0].toLowerCase();
  }

  // Every <a href="...">text</a> pair, so we can compare the promise with the
  // reality. This is where "misleading link text" detection happens.
  function findAnchors(html) {
    var re = /<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
    var out = [];
    var m;
    while ((m = re.exec(html)) !== null) {
      var href = (m[1] || m[2] || m[3] || '').trim();
      var parsed = PEA.urls.parseUrl(href);
      out.push({
        href: href,
        text: stripTags(m[4]),
        host: parsed.host,
        scheme: parsed.scheme,
        userinfo: parsed.userinfo
      });
    }
    return out;
  }

  /* ----------------------------------------------------------------------
     Scoring weights for HTML-source findings.
     ---------------------------------------------------------------------- */
  var WEIGHTS = {
    hidden_content: {
      points: 10, severity: 'high', category: 'Message source',
      title: 'Hidden text or elements in the message source',
      why: 'Content that is invisible on screen but present in the source is used to smuggle words past spam filters, or to show one thing to you and another to software.',
      advice: 'Treat any message with hidden content as untrustworthy and report it.'
    },
    embedded_login_form: {
      points: 14, severity: 'critical', category: 'Message source',
      title: 'The email itself contains a login form',
      why: 'Legitimate companies send you to their own website to sign in. A form inside the email collects whatever you type for whoever built the message.',
      advice: 'Never fill in a form inside an email. Go to the service through its official app or a bookmark.'
    },
    tracking_pixel: {
      points: 5, severity: 'low', category: 'Message source',
      title: 'Hidden tracking image (beacon pixel)',
      why: 'A tiny invisible image can tell the sender that you opened the message, when, and roughly where you were. It is not malicious by itself, but it confirms your address is live.',
      advice: 'Note that this tool did not load the image. Consider blocking remote images in your mail client to prevent this tracking.'
    },
    entity_obfuscation: {
      points: 6, severity: 'medium', category: 'Message source',
      title: 'Heavily obfuscated characters in the source',
      why: 'Long runs of encoded characters can hide the true text of a link or message from anyone reading the source, while still displaying normally in the inbox.',
      advice: 'Do not act on the message until you can see its true content, and report it to your security team.'
    },
    javascript_href: {
      points: 12, severity: 'high', category: 'Message source',
      title: 'Link runs a script instead of opening a page',
      why: 'A "javascript:" link executes code in your browser rather than navigating, which can be used to trigger downloads or fake login prompts.',
      advice: 'Do not click it. Report the message.'
    },
    data_uri_link: {
      points: 10, severity: 'high', category: 'Message source',
      title: 'Link embeds a whole page inside the address (data: URI)',
      why: 'A data: link carries a complete fake web page inside the message, so the address bar shows nothing recognisable and there may be no server to report.',
      advice: 'Do not click it. This technique has no legitimate place in a normal business email.'
    },
    misleading_link_text: {
      points: 12, severity: 'high', category: 'Links and actions',
      title: 'Link text does not match the real destination',
      why: 'The link displays one address but points to another. This is the single most common way people are tricked, because we read the link text rather than the underlying address.',
      advice: 'Never sign in through such a link. Reach the service through a route you control.'
    },
    remote_resources: {
      points: 0, severity: 'info', category: 'Message source',
      title: 'Remote images or stylesheets are referenced',
      why: 'The message loads content from an external host. Nothing was fetched here, but your mail client probably will when the message is opened.',
      advice: 'Consider blocking remote images in your mail client so that opening a message does not confirm your address is active.'
    }
  };

  function addHit(hits, id, match) {
    if (!hits[id]) { hits[id] = []; }
    if (match && hits[id].indexOf(match) === -1 && hits[id].length < 4) { hits[id].push(match); }
  }

  /* ----------------------------------------------------------------------
     analyseHtml(text) -> { isHtml, findings, anchorCount, remoteHosts }
     Only runs when the pasted text genuinely looks like HTML source.
     ---------------------------------------------------------------------- */
  function analyseHtml(text) {
    var html = String(text || '');
    if (!looksLikeHtml(html)) {
      return { isHtml: false, findings: [], anchorCount: 0, remoteHosts: [] };
    }

    var hits = {};

    // 1. Hidden content: invisible text or zero-size elements
    var hiddenRe = /(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?|opacity\s*:\s*0(?:\.0+)?)/gi;
    var hidden = html.match(hiddenRe) || [];
    if (hidden.length) {
      addHit(hits, 'hidden_content', hidden.slice(0, 3).join(' , '));
    }

    // 2. A login form embedded in the message
    var formTag = (html.match(/<form\b[^>]*>/i) || [''])[0];
    var hasPasswordInput = /<input\b[^>]*type\s*=\s*["']?password/i.test(html) ||
      /name\s*=\s*["']?(?:pass|password|pwd)["']?/i.test(html);
    if (formTag || hasPasswordInput) {
      addHit(hits, 'embedded_login_form', stripTags(formTag).slice(0, 100) || 'password input field found in the source');
    }

    // 3. Tracking pixels (1x1 or 0x0 remote images)
    var pixRe = /<img\b[^>]*width\s*=\s*["']?[01]\b[^>]*height\s*=\s*["']?[01]\b[^>]*>|<img\b[^>]*height\s*=\s*["']?[01]\b[^>]*width\s*=\s*["']?[01]\b[^>]*>/gi;
    var pix = html.match(pixRe) || [];
    if (pix.length) {
      addHit(hits, 'tracking_pixel', stripTags(pix[0]).slice(0, 90) || 'a 1x1 image element');
    }

    // 3b. Remote resources, listed for information only (0 points)
    var remoteHosts = [];
    var remoteRe = /(?:src|href|background)\s*=\s*["']https?:\/\/([^"'\/]+)/gi;
    var rm;
    while ((rm = remoteRe.exec(html)) !== null) {
      var host = rm[1].toLowerCase();
      if (host && remoteHosts.indexOf(host) === -1 && remoteHosts.length < 8) { remoteHosts.push(host); }
    }
    if (remoteHosts.length) { addHit(hits, 'remote_resources', remoteHosts.slice(0, 4).join(', ')); }

    // 4. Obfuscated characters
    var entities = (html.match(/&#x?[0-9a-f]{2,4};/gi) || []).length;
    var pctTags = (html.match(/%3c|%3e/gi) || []).length;
    if (entities >= 12 || pctTags >= 3) {
      addHit(hits, 'entity_obfuscation', entities + ' HTML entity codes and ' + pctTags + ' encoded tag characters');
    }

    // 5. Script-driven and embedded-page links
    if (/href\s*=\s*["']?\s*javascript:/i.test(html)) {
      addHit(hits, 'javascript_href', 'javascript: link found in the source');
    }
    if (/href\s*=\s*["']\s*data:/i.test(html)) {
      addHit(hits, 'data_uri_link', 'data: link found in the source');
    }

    // 6. Misleading link text: what you read versus where it goes
    var anchors = findAnchors(html);
    var mismatches = [];
    anchors.forEach(function (a) {
      if (!a.host) { return; }
      var shown = domainInText(a.text);
      var shownReg = shown ? U.registrableDomain(shown) : '';
      var realReg = U.registrableDomain(a.host);
      if (!realReg) { return; }
      if (shownReg && shownReg !== realReg) {
        mismatches.push('"' + a.text.slice(0, 60) + '" actually points to ' + a.host);
      } else if (!shownReg && L.URL_SHORTENERS.indexOf(realReg) !== -1) {
        mismatches.push('"' + a.text.slice(0, 60) + '" is a shortened link to ' + a.host);
      }
    });
    if (mismatches.length) { addHit(hits, 'misleading_link_text', mismatches.slice(0, 2).join(' ; ')); }

    var findings = Object.keys(hits).map(function (id) {
      var meta = WEIGHTS[id];
      return {
        id: id,
        source: 'html',
        category: meta.category,
        severity: meta.severity,
        points: meta.points,
        title: meta.title,
        why: meta.why,
        advice: meta.advice,
        matches: hits[id].slice(0, 4)
      };
    });

    return { isHtml: true, findings: findings, anchorCount: anchors.length, remoteHosts: remoteHosts };
  }

  PEA.html = {
    looksLikeHtml: looksLikeHtml,
    analyseHtml: analyseHtml,
    weights: WEIGHTS,
    findAnchors: findAnchors,
    stripTags: stripTags
  };
}(window.PEA = window.PEA || {}));


