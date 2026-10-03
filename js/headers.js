/* ==========================================================================
   Phishing Email Analyser — js/headers.js
   --------------------------------------------------------------------------
   If the visitor pastes the full raw message including its technical header
   block, we can check the parts the sender does not control quite so easily:
   who the message claims to come from, where replies would go, and what the
   receiving mail system recorded about SPF, DKIM and DMARC.

   WHAT THE AUTHENTICATION RESULTS ACTUALLY MEAN (plain English)
     SPF   - does the sending computer have permission to send for this domain?
     DKIM  - is the cryptographic signature on the message valid, so the
             content was not altered in transit?
     DMARC - does the domain's published policy agree that SPF/DKIM passed, and
             does it claim this "From" address at all?
   A "pass" is a good sign for that specific check. A "fail" is a genuine red
   flag, but on its own it is not proof of fraud: misconfigured mailing lists
   and forwarding regularly break authentication on legitimate mail.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var U = PEA.util;
  var L = PEA.lists;

  // Header names we recognise. Anything else is ignored so that a message body
  // accidentally starting with "Something: value" is not mistaken for headers.
  var HEADER_RE = /^([A-Za-z][A-Za-z0-9\-]{1,40})\s*:\s?([\s\S]*)$/;
  var STRONG_HEADERS = ['received', 'return-path', 'from', 'reply-to', 'subject',
    'message-id', 'authentication-results', 'dkim-signature', 'received-spf',
    'sender', 'delivered-to', 'envelope-to', 'x-spam-flag', 'x-spam-status'];

  /* ----------------------------------------------------------------------
     parse(text) -> { found, block, headers, body, lineCount }
     Header lines can wrap onto the next line (a "folded" header), so lines
     beginning with a space or tab are joined onto the previous value.
     ---------------------------------------------------------------------- */
  function parse(text) {
    var src = String(text || '');
    var lines = src.split(/\r?\n/);
    var collected = [];
    var headers = {};
    var lastKey = null;
    var blanksSeen = 0;
    var i;

    for (i = 0; i < lines.length && i < 120; i++) {
      var line = lines[i];

      if (line.trim() === '') {
        if (collected.length > 0) { blanksSeen++; if (blanksSeen >= 1) { i++; break; } }
        continue;
      }
      // Folded continuation of the previous header
      if (/^[ \t]/.test(line) && lastKey) {
        headers[lastKey] += ' ' + line.trim();
        collected.push(line);
        continue;
      }
      var m = HEADER_RE.exec(line);
      if (!m) {
        // A non-header line inside what looked like a header block: stop here.
        break;
      }
      var key = m[1].toLowerCase();
      headers[key] = m[2].trim();
      lastKey = key;
      collected.push(line);
    }

    var strongCount = 0;
    Object.keys(headers).forEach(function (k) {
      if (STRONG_HEADERS.indexOf(k) !== -1) { strongCount++; }
    });

    var found = collected.length >= 2 && strongCount >= 2;
    var body = found ? lines.slice(i).join('\n') : src;

    return {
      found: found,
      block: collected.join('\n'),
      headers: headers,
      body: body,
      lineCount: collected.length,
      rawLines: lines
    };
  }

  // Pull an email address out of a header value such as:
  //   "Microsoft Support" <no-reply@secure-microsoft.example>
  function parseAddress(value) {
    var v = String(value || '').trim();
    var angle = /<([^>]+)>/.exec(v);
    var address = angle ? angle[1].trim() : v.replace(/^\[|\]$/g, '').trim();
    var display = angle ? v.slice(0, angle.index).trim() : '';
    display = display.replace(/^["']|["']$/g, '').trim();
    var at = address.lastIndexOf('@');
    var domain = at !== -1 ? address.slice(at + 1).toLowerCase() : '';
    return { raw: v, address: address, domain: domain, display: display };
  }

  function authValue(headers, key) {
    var candidates = [];
    if (headers['authentication-results']) { candidates.push(headers['authentication-results']); }
    if (headers['arc-authentication-results']) { candidates.push(headers['arc-authentication-results']); }
    if (headers[key]) { candidates.push(headers[key]); }
    var blob = candidates.join(' ');
    var re = new RegExp('\\b' + key + '\\s*=\\s*([a-z]+)', 'i');
    var m = re.exec(blob);
    return m ? m[1].toLowerCase() : '';
  }

  /* ----------------------------------------------------------------------
     Scoring weights for header findings.
     ---------------------------------------------------------------------- */
  var WEIGHTS = {
    reply_to_mismatch: {
      points: 14, severity: 'high', category: 'Email headers',
      title: 'Reply-To points somewhere different from the From address',
      why: 'The sender is set up so that your reply goes to a different mailbox from the one the message claims to come from. This is common in phishing, because it routes your response to the attacker.',
      advice: 'Do not reply to the message. Contact the organisation using details from their official website.'
    },
    display_name_spoof: {
      points: 12, severity: 'high', category: 'Email headers',
      title: 'Display name claims a brand the address does not belong to',
      why: 'Mail clients show the friendly display name ("Microsoft Account Team") and hide the real address. Anyone can put any name there.',
      advice: 'Always check the actual address, not the name. Then reach the organisation through a route you control.'
    },
    free_mail_sender: {
      points: 10, severity: 'medium', category: 'Email headers',
      title: 'Corporate-looking message sent from a free mailbox provider',
      why: 'A message that claims to be from a company but is sent from a consumer mailbox service is a strong hint of impersonation, because real businesses send from their own domains.',
      advice: 'Treat the message as unverified and contact the organisation directly.'
    },
    return_path_mismatch: {
      points: 6, severity: 'medium', category: 'Email headers',
      title: 'Return-Path domain differs from the From domain',
      why: 'The Return-Path is where bounce messages go. A mismatch can indicate a bulk mailing platform, or that the message was not sent by the domain it claims. Both are common, so this scores moderately.',
      advice: 'Weigh this alongside the other findings rather than treating it as proof.'
    },
    spf_fail: {
      points: 8, severity: 'medium', category: 'Authentication',
      title: 'SPF failed',
      why: 'SPF confirms whether the sending computer was allowed to send mail for that domain. A failure means the message did not come from an authorised system for that domain.',
      advice: 'Do not trust the sender identity. This is a genuine technical red flag, though forwarding and mailing lists can also cause it.'
    },
    dkim_fail: {
      points: 8, severity: 'medium', category: 'Authentication',
      title: 'DKIM failed',
      why: 'DKIM is a cryptographic signature proving the message content was not altered in transit and was signed by the claimed domain. A failure means the signature did not verify.',
      advice: 'Treat the content as unverified. Do not click links or open attachments.'
    },
    dmarc_fail: {
      points: 10, severity: 'high', category: 'Authentication',
      title: 'DMARC failed',
      why: 'DMARC is the domain owner\u2019s published instruction about what to do when SPF and DKIM do not line up with the "From" address. A failure means the message failed the domain\u2019s own policy.',
      advice: 'Treat the message as suspicious. Report it rather than acting on it.'
    },
    spam_header: {
      points: 10, severity: 'medium', category: 'Email headers',
      title: 'Marked as spam by the receiving mail system',
      why: 'A gateway or mailbox rule already classified this message as spam. That judgement was made by your own systems, independent of anything in this tool.',
      advice: 'Do not act on the message. If you are unsure, ask your IT or security team to review it.'
    },
    message_id_mismatch: {
      points: 5, severity: 'low', category: 'Email headers',
      title: 'Message-ID domain does not match the sender domain',
      why: 'The Message-ID is normally generated by the sending system using its own domain. A mismatch is a weak hint of hand-crafted or relayed mail.',
      advice: 'A single mismatch means little on its own; weigh it with everything else.'
    },
    missing_headers: {
      points: 4, severity: 'low', category: 'Email headers',
      title: 'Standard headers are missing',
      why: 'A genuine message sent through normal mail systems almost always carries a Date and a Message-ID. Their absence suggests the headers were constructed by hand or stripped.',
      advice: 'Treat the message with caution and verify with the sender.'
    }
  };

  // Does a free-text display name contain a brand we are watching for?
  function brandFromText(text) {
    var t = String(text || '').toLowerCase();
    var found = null;
    L.BRANDS.forEach(function (brand) {
      if (found) { return; }
      if (brand.tokens.some(function (tok) { return tok.length >= 4 && t.indexOf(tok) !== -1; })) {
        found = brand;
      }
    });
    return found;
  }

  /* ----------------------------------------------------------------------
     analyse(text) -> { found, findings, notes, summary, auth, parsed }
     `notes` holds explanatory zero-point observations (such as a successful
     SPF result) so the user sees the whole picture, not just the warnings.
     ---------------------------------------------------------------------- */
  function analyse(text) {
    var parsed = parse(text);
    var notes = [];

    if (!parsed.found) {
      notes.push({
        severity: 'info',
        title: 'No raw email headers found',
        text: 'This text does not contain a raw header block, so SPF, DKIM, DMARC, Reply-To and Return-Path could not be checked. To include them, open the message in your mail client, choose "View source" or "Show original", and copy everything.'
      });
      return { found: false, findings: [], notes: notes, summary: null, auth: null, parsed: parsed };
    }

    var h = parsed.headers;
    var findings = [];

    function add(id, matches) {
      var meta = WEIGHTS[id];
      findings.push({
        id: id, source: 'header', category: meta.category, severity: meta.severity,
        points: meta.points, title: meta.title, why: meta.why, advice: meta.advice,
        matches: matches || []
      });
    }

    var from = parseAddress(h['from']);
    var replyTo = h['reply-to'] ? parseAddress(h['reply-to']) : null;
    var returnPath = h['return-path'] ? parseAddress(h['return-path']) : null;
    var messageId = h['message-id'] || '';
    var fromReg = U.registrableDomain(from.domain);

    var spf = authValue(h, 'spf');
    var dkim = authValue(h, 'dkim');
    var dmarc = authValue(h, 'dmarc');
    if (!spf && h['received-spf']) {
      var rs = /^\s*(pass|fail|softfail|neutral|none|permerror|temperror)/i.exec(h['received-spf']);
      if (rs) { spf = rs[1].toLowerCase(); }
    }

    // --- 1. Reply-To points somewhere else ------------------------------
    if (replyTo && replyTo.domain && from.domain &&
      U.registrableDomain(replyTo.domain) !== fromReg) {
      add('reply_to_mismatch', ['From: ' + from.address, 'Reply-To: ' + replyTo.address]);
    }

    // --- 2. Display name claims a brand the address does not own --------
    var claimed = brandFromText(from.display);
    if (claimed && from.domain && claimed.domains.indexOf(fromReg) === -1) {
      add('display_name_spoof', ['"' + from.display + '" <' + from.address + '>']);
    }

    // --- 3. Corporate-sounding message from a consumer mailbox ----------
    if (from.domain && L.FREE_MAIL_DOMAINS.indexOf(fromReg) !== -1) {
      var corporateContext = claimed ||
        /\b(?:finance|accounts|billing|hr|payroll|support|security|invoice|bank|remittance)\b/i.test(from.display + ' ' + (h['subject'] || ''));
      if (corporateContext) {
        add('free_mail_sender', [from.address]);
      }
    }

    // --- 4. Return-Path mismatch ----------------------------------------
    if (returnPath && returnPath.domain && from.domain &&
      U.registrableDomain(returnPath.domain) !== fromReg) {
      add('return_path_mismatch', ['From: ' + from.address, 'Return-Path: ' + returnPath.address]);
    }

    // --- 5. SPF / DKIM / DMARC -----------------------------------------
    if (spf === 'fail' || spf === 'permerror') {
      add('spf_fail', ['spf=' + spf]);
    } else if (spf === 'pass') {
      notes.push({ severity: 'ok', title: 'SPF passed', text: 'The sending system was authorised to send mail for the From domain. That is a positive sign for this message, although a criminal can still pass SPF for a domain they own.' });
    } else if (spf) {
      notes.push({ severity: 'info', title: 'SPF result: ' + spf, text: 'SPF did not return a clear pass (' + spf + '). Forwarding and mailing lists often cause this, so on its own it means little.' });
    }

    if (dkim === 'fail') {
      add('dkim_fail', ['dkim=fail']);
    } else if (dkim === 'pass') {
      notes.push({ severity: 'ok', title: 'DKIM passed', text: 'The message carries a valid cryptographic signature, so its content matches what the signing domain sent.' });
    }

    if (dmarc === 'fail') {
      add('dmarc_fail', ['dmarc=fail']);
    } else if (dmarc === 'pass') {
      notes.push({ severity: 'ok', title: 'DMARC passed', text: 'The From domain\u2019s own published policy was satisfied. This is the strongest of the three checks.' });
    }

    var authPresent = !!(spf || dkim || dmarc || h['authentication-results'] || h['dkim-signature']);
    if (!authPresent) {
      notes.push({
        severity: 'info',
        title: 'No authentication results in these headers',
        text: 'The pasted headers do not include Authentication-Results, so SPF, DKIM and DMARC could not be evaluated at all. Missing results are not evidence of fraud: many providers only add them at the final delivery step.'
      });
    }

    // --- 6. Already flagged as spam by the receiving system --------------
    var spamFlag = /^\s*yes/i.test(h['x-spam-flag'] || '');
    var spamStatus = /\byes\b/i.test((h['x-spam-status'] || '').slice(0, 40));
    if (spamFlag || spamStatus) {
      add('spam_header', [h['x-spam-flag'] ? 'X-Spam-Flag: ' + h['x-spam-flag'] : 'X-Spam-Status: ' + (h['x-spam-status'] || '').slice(0, 60)]);
    }

    // --- 7. Message-ID domain mismatch ----------------------------------
    var msgDomain = '';
    var midMatch = /@([a-z0-9.\-]+)[>\s]/i.exec(messageId + ' ');
    if (midMatch) { msgDomain = midMatch[1].toLowerCase().replace(/\.$/, ''); }
    if (msgDomain && from.domain && U.registrableDomain(msgDomain) !== fromReg) {
      add('message_id_mismatch', ['Message-ID: ' + messageId.slice(0, 90)]);
    }

    // --- 8. Missing Date / Message-ID -----------------------------------
    // Only worth reporting when the visitor pasted what looks like a FULL raw
    // message. If they copied just a few headers by hand, the absence of Date
    // or Message-ID tells us nothing.
    var looksLikeFullRaw = !!(h['received'] || h['return-path'] || h['authentication-results'] ||
      h['dkim-signature'] || h['mime-version'] || h['content-type']);
    if (looksLikeFullRaw && (!h['date'] || !h['message-id'])) {
      add('missing_headers', [!h['date'] ? 'Date header missing' : 'Message-ID header missing']);
    }

    var summary = {
      from: from.address,
      fromDisplay: from.display,
      fromDomain: from.domain,
      fromRegistrable: fromReg,
      replyTo: replyTo ? replyTo.address : '',
      replyToDomain: replyTo ? replyTo.domain : '',
      returnPath: returnPath ? returnPath.address : '',
      subject: h['subject'] || '',
      date: h['date'] || '',
      messageId: messageId,
      receivedCount: parsed.rawLines.filter(function (l) { return /^received\s*:/i.test(l); }).length,
      spf: spf, dkim: dkim, dmarc: dmarc,
      authenticationResults: h['authentication-results'] || '',
      headerCount: Object.keys(h).length
    };

    return {
      found: true,
      findings: findings,
      notes: notes,
      summary: summary,
      auth: { spf: spf, dkim: dkim, dmarc: dmarc },
      parsed: parsed
    };
  }

  PEA.headers = {
    parse: parse,
    parseAddress: parseAddress,
    analyse: analyse,
    weights: WEIGHTS,
    brandFromText: brandFromText
  };
}(window.PEA = window.PEA || {}));



