/* ==========================================================================
   Phishing Email Analyser — js/rules.js
   --------------------------------------------------------------------------
   This file is the "brain's memory": every detection rule and every score
   weight lives here, in one place, as plain data.

   HOW THE SCORING WORKS (plain English)
   ------------------------------------
   Each rule below has a `points` value. If the rule matches the pasted email,
   that many points are added to the total. At the end the total is capped at
   100. Because every point comes from a named rule with a written reason, the
   final number is always explainable. There is no hidden weighting, no machine
   learning and no guessing.

   Severity labels (used for colour-coding and sorting):
     critical | high | medium | low | info
   "info" rules add 0 points. They exist to give the user context.

   The rules here are deliberately transparent, which means they are also
   deliberately imperfect. They match *language patterns*, not meaning. That is
   exactly why the app never claims to decide whether an email is malicious.
   ========================================================================== */
(function (PEA) {
  'use strict';

  /* ----------------------------------------------------------------------
     Domain-suffix tables
     ---------------------------------------------------------------------- */

  // Multi-part public suffixes, so that "login.barclays.co.uk" is understood
  // as being registered under "co.uk" rather than "uk".
  var MULTI_PART_SUFFIXES = [
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'ac.uk', 'net.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz',
    'co.za', 'org.za', 'co.in', 'net.in', 'org.in', 'co.jp', 'ne.jp', 'or.jp',
    'com.br', 'net.br', 'org.br', 'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk',
    'com.cn', 'com.tw', 'com.my', 'com.ph', 'com.vn', 'co.kr', 'co.id', 'co.il', 'co.th'
  ];

  // Registry-wide suffixes that are cheap or free to register and therefore
  // heavily used in short-lived phishing campaigns. Being on this list is NOT
  // proof of anything — plenty of legitimate sites use them — but combined with
  // other signals it is a genuine warning sign.
  var SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'icu', 'click', 'link', 'work', 'buzz',
    'rest', 'country', 'stream', 'download', 'loan', 'gdn', 'bid', 'win', 'mom', 'party',
    'review', 'science', 'zip', 'mov', 'kim', 'su', 'pw', 'cc', 'ws', 'live', 'online',
    'site', 'info', 'biz', 'best', 'cfd', 'sbs', 'cyou', 'monster', 'quest', 'bar', 'shop',
    'club', 'support', 'help', 'services', 'email', 'today', 'life', 'world', 'space'
  ];

  // URL shorteners: the destination is hidden until the link is clicked, which
  // is why attackers and legitimate marketers both use them. We never follow
  // them — following a link would mean making a network request.
  var URL_SHORTENERS = [
    'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in', 's.id',
    'shorte.st', 'adf.ly', 'bl.ink', 'clck.ru', 'v.gd', 'urlz.fr', 'short.gy', 't.ly',
    'cutt.us', 'soo.gd', 'x.co', 'mcaf.ee', 'qr.ae', 'u.to', 'snip.ly', 'short.io'
  ];

  // Consumer mailbox providers. Legitimate businesses rarely send invoices or
  // security alerts from these, but they are trivial for an attacker to use.
  var FREE_MAIL_DOMAINS = [
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'hotmail.co.uk',
    'live.com', 'live.co.uk', 'msn.com', 'yahoo.com', 'yahoo.co.uk', 'ymail.com',
    'aol.com', 'gmx.com', 'gmx.de', 'mail.com', 'zoho.com', 'protonmail.com',
    'proton.me', 'yandex.com', 'yandex.ru', 'mail.ru', 'inbox.com', 'icloud.com', 'me.com'
  ];

  /* ----------------------------------------------------------------------
     Brands that are impersonated most often.
     `tokens`  = words that appear in the text or inside a hostname
     `domains` = the registrable domains that actually belong to the brand
     Used for: display-name spoofing, "brand mentioned in a domain that is not
     theirs", and near-miss (typosquatted) domain detection.
     ---------------------------------------------------------------------- */
  var BRANDS = [
    { name: 'Microsoft', tokens: ['microsoft', 'office365', 'microsoft365', 'onedrive', 'sharepoint', 'outlook', 'msonline'], domains: ['microsoft.com', 'office.com', 'office365.com', 'microsoft365.com', 'microsoftonline.com', 'sharepoint.com', 'outlook.com', 'live.com', 'azure.com'] },
    { name: 'Apple', tokens: ['apple', 'icloud', 'appleid', 'itunes'], domains: ['apple.com', 'icloud.com', 'itunes.com'] },
    { name: 'Google', tokens: ['google', 'gmail', 'googlemail', 'youtube'], domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com'] },
    { name: 'PayPal', tokens: ['paypal'], domains: ['paypal.com', 'paypal.co.uk', 'paypal.me'] },
    { name: 'Amazon', tokens: ['amazon', 'amazonprime'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.co.jp', 'aws.amazon.com'] },
    { name: 'Netflix', tokens: ['netflix'], domains: ['netflix.com'] },
    { name: 'Meta / Facebook', tokens: ['facebook', 'instagram', 'whatsapp'], domains: ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com'] },
    { name: 'LinkedIn', tokens: ['linkedin'], domains: ['linkedin.com', 'lnkd.in'] },
    { name: 'Dropbox', tokens: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'Adobe', tokens: ['adobe', 'acrobat'], domains: ['adobe.com'] },
    { name: 'DocuSign', tokens: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Bank of America', tokens: ['bankofamerica'], domains: ['bankofamerica.com'] },
    { name: 'Chase', tokens: ['chase', 'jpmorgan'], domains: ['chase.com', 'jpmorgan.com'] },
    { name: 'Wells Fargo', tokens: ['wellsfargo'], domains: ['wellsfargo.com'] },
    { name: 'Barclays', tokens: ['barclays'], domains: ['barclays.co.uk', 'barclays.com'] },
    { name: 'HSBC', tokens: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk'] },
    { name: 'Lloyds Bank', tokens: ['lloyds', 'lloydsbank'], domains: ['lloydsbank.com', 'lloydsbank.co.uk'] },
    { name: 'NatWest', tokens: ['natwest'], domains: ['natwest.com', 'natwest.co.uk'] },
    { name: 'Santander', tokens: ['santander'], domains: ['santander.com', 'santander.co.uk'] },
    { name: 'Nationwide', tokens: ['nationwide'], domains: ['nationwide.co.uk'] },
    { name: 'Revolut', tokens: ['revolut'], domains: ['revolut.com'] },
    { name: 'Wise', tokens: ['wise', 'transferwise'], domains: ['wise.com', 'transferwise.com'] },
    { name: 'Coinbase', tokens: ['coinbase'], domains: ['coinbase.com'] },
    { name: 'Binance', tokens: ['binance'], domains: ['binance.com'] },
    { name: 'Steam', tokens: ['steam', 'steampowered'], domains: ['steampowered.com', 'steamcommunity.com'] },
    { name: 'Spotify', tokens: ['spotify'], domains: ['spotify.com'] },
    { name: 'DHL', tokens: ['dhl'], domains: ['dhl.com', 'dhl.co.uk', 'dhl.de'] },
    { name: 'FedEx', tokens: ['fedex'], domains: ['fedex.com'] },
    { name: 'UPS', tokens: ['unitedparcel'], domains: ['ups.com'] },
    { name: 'USPS', tokens: ['usps'], domains: ['usps.com', 'usps.gov'] },
    { name: 'Royal Mail', tokens: ['royalmail'], domains: ['royalmail.com', 'royalmail.co.uk'] },
    { name: 'Evri', tokens: ['evri', 'myhermes'], domains: ['evri.com', 'myhermes.co.uk'] },
    { name: 'DPD', tokens: ['dpd'], domains: ['dpd.com', 'dpd.co.uk', 'dpdlocal.co.uk'] },
    { name: 'HMRC', tokens: ['hmrc'], domains: ['hmrc.gov.uk', 'gov.uk'] },
    { name: 'IRS', tokens: ['irs'], domains: ['irs.gov'] },
    { name: 'eBay', tokens: ['ebay'], domains: ['ebay.com', 'ebay.co.uk'] },
    { name: 'Visa', tokens: ['visa'], domains: ['visa.com', 'visa.co.uk'] },
    { name: 'Mastercard', tokens: ['mastercard'], domains: ['mastercard.com', 'mastercard.co.uk'] },
    { name: 'Airbnb', tokens: ['airbnb'], domains: ['airbnb.com', 'airbnb.co.uk'] },
    { name: 'Booking.com', tokens: ['booking'], domains: ['booking.com'] },
    { name: 'Uber', tokens: ['uber'], domains: ['uber.com'] },
    { name: 'Xbox', tokens: ['xbox'], domains: ['xbox.com'] },
    { name: 'PlayStation', tokens: ['playstation'], domains: ['playstation.com'] }
  ];

  /* ----------------------------------------------------------------------
     Attachment extension groups.
     ---------------------------------------------------------------------- */
  var ATTACHMENT_EXTENSIONS = {
    // Files that can run code the moment they are opened. Highest risk.
    executable: ['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'bat', 'cmd', 'pif', 'ps1', 'psm1', 'jar', 'lnk', 'msi', 'reg', 'chm', 'apk', 'dll', 'cpl', 'url', 'sct', 'xnk', 'iqy', 'slk'],
    // Disk images: opening them in Windows can bypass "Mark of the Web" warnings.
    diskImage: ['iso', 'img', 'vhd', 'vhdx', 'vmdk', 'udf'],
    // Archives are often used to wrap the real payload.
    archive: ['zip', 'rar', '7z', 'tar', 'gz', 'cab', 'ace', 'arj', 'lzh'],
    // Office formats that are allowed to contain macros.
    macroEnabled: ['docm', 'dotm', 'xlsm', 'xltm', 'xlsb', 'pptm', 'potm', 'ppam', 'xlam', 'sldm'],
    // Formats that can carry script or unusual content despite looking harmless.
    unusual: ['rtf', 'svg', 'html', 'htm', 'mht', 'eml', 'msg', 'wiz', 'doc', 'xls']
  };

  // Every extension we recognise, flattened, so filename extraction can spot
  // candidate filenames inside plain text.
  var ALL_EXTENSIONS = (function () {
    var out = [];
    for (var k in ATTACHMENT_EXTENSIONS) {
      if (Object.prototype.hasOwnProperty.call(ATTACHMENT_EXTENSIONS, k)) {
        out = out.concat(ATTACHMENT_EXTENSIONS[k]);
      }
    }
    // Harmless extensions we still want to recognise as "a file was mentioned".
    out = out.concat(['pdf', 'docx', 'xlsx', 'pptx', 'csv', 'txt', 'png', 'jpg', 'jpeg']);
    return out.filter(function (v, i) { return out.indexOf(v) === i; });
  }());

  /* ----------------------------------------------------------------------
     Shared helpers
     (kept in this file so every other module can use PEA.util.*)
     ---------------------------------------------------------------------- */

  // Work out the "registrable" domain: the part someone actually bought.
  // e.g. login.secure.barclays.co.uk -> barclays.co.uk
  function registrableDomain(host) {
    if (!host) { return ''; }
    var h = String(host).toLowerCase().replace(/\.$/, '').trim();
    if (!h) { return ''; }
    var parts = h.split('.');
    if (parts.length <= 2) { return h; }
    var lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.indexOf(lastTwo) !== -1 && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return lastTwo;
  }

  // The main word of a registrable domain, without its suffix:
  //   barclays.co.uk -> barclays      paypal.com -> paypal
  function domainCore(host) {
    var r = registrableDomain(host);
    if (!r) { return ''; }
    var parts = r.split('.');
    var suffixLen = (MULTI_PART_SUFFIXES.indexOf(parts.slice(-2).join('.')) !== -1) ? 3 : 2;
    if (parts.length >= suffixLen) { parts = parts.slice(0, parts.length - (suffixLen - 1)); }
    return parts.join('.');
  }

  function lastTld(host) {
    var parts = String(host || '').toLowerCase().split('.');
    return parts.length ? parts[parts.length - 1] : '';
  }

  // Is this host written as a bare IP address (e.g. 203.0.113.45)?
  function isIpAddressHost(host) {
    var h = String(host || '').replace(/^\[|\]$/g, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
      return h.split('.').every(function (o) { return Number(o) >= 0 && Number(o) <= 255; });
    }
    return h.indexOf(':') !== -1 && /^[0-9a-f:.]+$/i.test(h); // IPv6
  }

  // Classic Levenshtein edit distance, used for "looks-like" domains such as
  // micros0ft.com or arnazon.com. Only short strings are compared.
  function editDistance(a, b) {
    a = String(a || ''); b = String(b || '');
    if (a === b) { return 0; }
    if (!a.length) { return b.length; }
    if (!b.length) { return a.length; }
    var prev = [], cur = [], i, j;
    for (j = 0; j <= b.length; j++) { prev[j] = j; }
    for (i = 1; i <= a.length; i++) {
      cur[0] = i;
      for (j = 1; j <= b.length; j++) {
        var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = cur.slice();
    }
    return prev[b.length];
  }

  // Does this text contain characters outside plain ASCII? (homoglyph check)
  function hasNonAscii(s) { return /[^\x00-\x7F]/.test(String(s || '')); }

  // Convert "defanged" URLs that people paste for safety back into a form we
  // can inspect: hxxp:// -> http://, evil[.]com -> evil.com, evil(.)com.
  function normalizeDefanged(s) {
    return String(s || '')
      .replace(/h(?:xx|tt)ps?:\/\//gi, function (m) { return /hxxps|https/i.test(m) ? 'https://' : 'http://'; })
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)/gi, '.')
      .replace(/\[\s*@\s*\]|\(\s*@\s*\)|\[at\]/gi, '@');
  }

  // Escaping helper. Text copied from a pasted email must be inserted into the
  // page as text, never as markup. ui.js uses this everywhere.
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  PEA.util = {
    registrableDomain: registrableDomain,
    domainCore: domainCore,
    lastTld: lastTld,
    isIpAddressHost: isIpAddressHost,
    editDistance: editDistance,
    hasNonAscii: hasNonAscii,
    normalizeDefanged: normalizeDefanged,
    escapeHtml: escapeHtml
  };

  PEA.lists = {
    MULTI_PART_SUFFIXES: MULTI_PART_SUFFIXES,
    SUSPICIOUS_TLDS: SUSPICIOUS_TLDS,
    URL_SHORTENERS: URL_SHORTENERS,
    FREE_MAIL_DOMAINS: FREE_MAIL_DOMAINS,
    BRANDS: BRANDS,
    ATTACHMENT_EXTENSIONS: ATTACHMENT_EXTENSIONS,
    ALL_EXTENSIONS: ALL_EXTENSIONS
  };

  // ======================================================================
  // BODY RULES — language patterns found in the message text.
  // Each entry has: id, category, severity, points, title, why, advice and
  // one or more `patterns` (regular expressions). Any single match fires the
  // rule and adds `points` to the score, with the matched text shown to the
  // user so nothing is hidden.
  // ======================================================================
  var BODY_RULES = [
    {
      id: 'password_request',
      category: 'Credentials',
      severity: 'critical',
      points: 18,
      title: 'Asks for a password',
      why: 'No legitimate organisation asks you to send, type or confirm your password by email. This is the single most reliable sign of a credential-phishing message.',
      advice: 'Never enter a password reached from an email link. If you are worried, open the service by typing its address yourself or use its official app.',
      patterns: [
        /\b(?:enter|provide|confirm|verify|update|re-?enter|send|submit|type|share|supply|validate)\b[^.!?\n]{0,45}\bpassword\b/i,
        /\bpassword\b[^.!?\n]{0,45}\b(?:verify|confirm|reset|update|continue|restore|unlock|expire)/i,
        /\b(?:username|user id|login)\b\s*(?:and|&)\s*(?:password|passphrase)\b/i,
        /\bcurrent password\b/i,
        /\bchange your password\b[^.!?\n]{0,40}\b(?:click|here|link|immediately|now)/i
      ]
    },
    {
      id: 'mfa_code_request',
      category: 'Credentials',
      severity: 'critical',
      points: 16,
      title: 'Asks for a one-time / verification code',
      why: 'A verification code is the second half of your login. Anyone asking you to read one out, type one in or forward one is trying to complete a sign-in as you. This is how "MFA fatigue" and real-time phishing work.',
      advice: 'Treat any request for a login or verification code as hostile. Never share it, even with someone who claims to be from IT support.',
      patterns: [
        /\b(?:one[- ]time|otp|verification|security|authentication|2fa|mfa|login|sign[- ]?in|sms)\s*code\b/i,
        /\b(?:6|six)[- ]digit code\b/i,
        /\benter the code\b/i,
        /\bshare (?:the |this |your )?(?:code|otp|pin)\b/i,
        /\bcode (?:you|that you|which you)(?:'ve| have)? just received\b/i,
        /\bapprove the (?:sign[- ]?in|login|request|push notification)\b/i
      ]
    },
    {
      id: 'credential_harvesting',
      category: 'Credentials',
      severity: 'high',
      points: 12,
      title: 'Credential-harvesting language ("verify your account")',
      why: 'Phrases such as "verify your account" or "confirm your identity" exist to push you towards a fake login page. They invent a reason for you to hand over a username and password.',
      advice: 'Do not follow the email to a login page. Sign in through the official app or website instead, and check there whether the alert is genuine.',
      patterns: [
        /\b(?:verify|confirm|validate|update|restore|reactivate|unlock|secure|upgrade)\s+(?:your\s+)?(?:account|identity|credentials|login|sign[- ]?in|details|information|profile|mailbox)\b/i,
        /\bsign in to (?:verify|confirm|restore|unlock|reactivate)\b/i,
        /\bre-?authenticate\b/i,
        /\bclick (?:here|below|the link)\b[^.!?\n]{0,30}\b(?:verify|confirm|restore|unlock|update|secure)\s+(?:your\s+)?(?:account|identity|login|sign[- ]?in|credentials|details|information|profile|mailbox)\b/i,
        /\baccount (?:verification|validation|confirmation)\b/i,
        /\bconfirm your identity\b/i
      ]
    },
    {
      id: 'account_threat',
      category: 'Pressure tactics',
      severity: 'high',
      points: 14,
      title: 'Threatens to suspend, close or lock the account',
      why: 'Fear of losing access is the most common lever in phishing. Legitimate services rarely threaten immediate closure by email, and never use that threat to demand a login or a payment.',
      advice: 'Slow down. Check the claim by logging in through the official app or website, then contact the organisation through a channel you already trust.',
      patterns: [
        /\b(?:account|mailbox|profile|subscription|service|access)\b[^.!?\n]{0,45}\b(?:suspend|suspension|terminat\w*|clos(?:e|ed|ure)|deactivat\w*|disabl\w*|blocked|locked|restricted|deleted|expir\w*)/i,
        /\bwill be (?:suspend\w*|clos\w*|deactivat\w*|terminat\w*|delet\w*|locked)\b/i,
        /\bpermanently (?:suspend\w*|clos\w*|delet\w*|block\w*|lock\w*)\b/i,
        /\blose (?:access|your account|all your)\b/i,
        /\bwithin \d+\s*(?:hours?|hrs?|days?|minutes?)\b[^.!?\n]{0,45}\b(?:or|otherwise|fail\w*|risk\w*)/i
      ]
    },
    {
      id: 'urgency_pressure',
      category: 'Pressure tactics',
      severity: 'medium',
      points: 10,
      title: 'Urgency and pressure language',
      why: 'Deadlines and "act now" wording are engineered to stop you checking. Urgency alone is not proof of fraud because real organisations do send reminders, so this rule scores moderately rather than highly.',
      advice: 'Give yourself a minute. A genuine organisation will still be there tomorrow, and you can verify the message at your own pace.',
      patterns: [
        /\b(?:immediate(?:ly)?|urgent(?:ly)?|as soon as possible|asap|right away|without delay|prompt action|act now|time[- ]sensitive|final (?:notice|warning|reminder|chance)|last (?:chance|warning|reminder)|expires? (?:today|soon|tonight|in \d+)|don'?t (?:delay|ignore|wait))\b/i,
        /\bwithin the next \d+\s*(?:hours?|hrs?|minutes?|days?)\b/i,
        /\b\d{1,3}\s*(?:hours?|hrs?|minutes?)\b[^.!?\n]{0,25}\b(?:to (?:respond|act|comply|verify|confirm|pay)|remaining)\b/i
      ]
    },
    {
      id: 'secrecy_request',
      category: 'Pressure tactics',
      severity: 'medium',
      points: 8,
      title: 'Asks you to keep it secret or not tell anyone',
      why: 'Requests for secrecy are a hallmark of business email compromise. There is no legitimate business process that requires you to hide a payment or a change of details from your colleagues.',
      advice: 'Treat secrecy requests as a red flag and discuss the message with a colleague or your security team before acting.',
      patterns: [
        /\b(?:do not|don'?t|please don'?t|kindly do not|never)\s+(?:tell|inform|discuss|share|mention|notify|contact)\b/i,
        /\bkeep (?:this|it)\s+(?:confidential|private|between us|secret|quiet)\b/i,
        /\bconfidential (?:matter|transaction|business|request)\b/i,
        /\bthis is (?:a )?(?:strictly )?confidential\b/i
      ]
    },
    {
      id: 'unusual_payment',
      category: 'Money and payments',
      severity: 'critical',
      points: 16,
      title: 'Payment requested by gift card, voucher, wire transfer or crypto',
      why: 'Gift card codes, vouchers, money transfers and cryptocurrency are irreversible and hard to trace. Genuine organisations use traceable payment methods and proper invoicing.',
      advice: 'Stop. Do not buy gift cards and do not send money. Verify the request by phoning the person or organisation on a number you already have.',
      patterns: [
        /\bgift ?cards?\b/i,
        /\b(?:itunes|google play|amazon|steam|apple|walmart|target|vanilla|sainsbury'?s|tesco|prepaid)\b[^.!?\n]{0,25}\b(?:card|voucher|code)\b/i,
        /\b(?:wire transfer|bank transfer|money transfer)\b/i,
        /\b(?:western union|moneygram)\b/i,
        /\b(?:cryptocurrency|bitcoin|btc|ethereum|usdt|crypto wallet)\b/i,
        /\brecharge (?:card|voucher)\b/i
      ]
    },
    {
      id: 'bank_details_change',
      category: 'Money and payments',
      severity: 'critical',
      points: 15,
      title: 'Asks to change bank or payment details',
      why: 'Changing bank details by email is the core of invoice fraud and payment-diversion scams. One successful change can redirect a real payment into a criminal account.',
      advice: 'Never change payment details based on an email. Confirm the new details using a phone number you already have on file.',
      patterns: [
        /\b(?:update|change|amend|revise|correct|replace)\b[^.!?\n]{0,35}\b(?:bank|payment|remittance|billing|account)\s*(?:details|information|instructions|number)\b/i,
        /\bnew (?:bank|account|payment) details\b/i,
        /\bupdated (?:banking|bank|payment|remittance)\s*(?:details|instructions|information)\b/i,
        /\bchange of (?:bank|banking|payment) details\b/i,
        /\bnew (?:sort code|iban|account number|routing number|bsb)\b/i,
        /\bremittance (?:details|instructions|advice)\b/i
      ]
    },
    {
      id: 'unexpected_invoice',
      category: 'Money and payments',
      severity: 'medium',
      points: 9,
      title: 'Unexpected invoice or overdue-payment language',
      why: 'Fake invoices are a favourite of both mass phishing and targeted fraud. A surprise bill for something you did not buy is a warning sign rather than a payment reminder.',
      advice: 'Check the invoice against your own records before doing anything, and contact the supplier using contact details you already have.',
      patterns: [
        /\b(?:outstanding|unpaid|overdue|due) (?:invoice|payment|balance|amount|bill)\b/i,
        /\bplease find (?:attached|enclosed)\b[^.!?\n]{0,35}\binvoice\b/i,
        /\binvoice (?:is )?attached\b/i,
        /\bpay the (?:attached|enclosed|outstanding) invoice\b/i,
        /\bpayment (?:is )?(?:overdue|now due|past due|required)\b/i
      ]
    },
    {
      id: 'bec_authority',
      category: 'Impersonation',
      severity: 'high',
      points: 12,
      title: 'Impersonates an executive or an authority figure',
      why: 'Business email compromise often impersonates a CEO, director or official body so that staff act without questioning. Authority plus urgency plus a payment request is the classic pattern.',
      advice: 'Verify the request in person or by calling a number you already have. Never rely on contact details supplied inside the message.',
      patterns: [
        /\b(?:chief executive|ceo|cfo|coo|managing director|finance director|your boss|the director|head of (?:finance|department|accounts))\b/i,
        /\b(?:i am|this is)\s+(?:the\s+)?(?:ceo|director|it (?:department|support|helpdesk|team)|system administrator|administrator|hr department)\b/i,
        /\bon behalf of\b[^.!?\n]{0,30}\b(?:ceo|cfo|director|management|executive)\b/i,
        /\b(?:hmrc|irs|tax (?:office|authority|department)|law enforcement|police|interpol)\b[^.!?\n]{0,30}\b(?:action|case|investigation|refund|notice|penalty|arrest)/i
      ]
    },
    {
      id: 'generic_impersonation',
      category: 'Impersonation',
      severity: 'medium',
      points: 8,
      title: 'Impersonates a brand or support team in general terms',
      why: 'Messages that describe themselves as "the Microsoft support team" or "your bank\u2019s security team", without naming a person you can check, are typical of mass phishing.',
      advice: 'Ignore the claim of identity inside the email and verify the message through the official website or app.',
      patterns: [
        /\b(?:microsoft|apple|google|paypal|amazon|netflix|barclays|hsbc|lloyds|natwest|santander|dhl|fedex|ups|dpd|hmrc|facebook|instagram)\b[^.!?\n]{0,25}\b(?:support|security team|customer (?:service|care)|service team|helpdesk|account team|team)\b/i,
        /\b(?:your|the)\s+(?:it\s+|technical\s+|tech\s+)?(?:support|helpdesk|help desk|service desk|security|billing|account|fraud)\s+(?:team|department|desk)\b/i,
        /\bwe are (?:your|the)\s+(?:bank|provider|service provider|account team)\b/i
      ]
    },
    {
      id: 'generic_greeting',
      category: 'Impersonation',
      severity: 'low',
      points: 5,
      title: 'Generic greeting instead of your name',
      why: 'A company you really deal with normally knows your name. "Dear Customer" suggests the sender holds a list of addresses rather than a list of customers. On its own it means very little, so it scores low.',
      advice: 'Treat this as one small clue rather than a conclusion, and weigh it with the other findings.',
      patterns: [
        /\b(?:dear|hello|hi|attention)\s+(?:customer|user|member|client|valued (?:customer|client)|account holder|sir\/madam|friend)\b/i,
        /\bdear (?:all|colleague|staff)\b/i
      ]
    },
    {
      id: 'security_alert_language',
      category: 'Pressure tactics',
      severity: 'high',
      points: 10,
      title: 'Claims a suspicious sign-in or compromised activity',
      why: 'Fake security alerts are designed to make you log in immediately "to secure" the account, on a page controlled by the attacker.',
      advice: 'Open the service directly through its official app or by typing the address yourself, and check for genuine security alerts there.',
      patterns: [
        /\b(?:unusual|suspicious|unrecognized|unrecognised|unauthorised|unauthorized|malicious)\s+(?:sign[- ]?in|login|log[- ]?in|activity|access|device|attempt)\b/i,
        /\bwe (?:detected|noticed|blocked|observed)\b[^.!?\n]{0,40}\b(?:activity|attempt|sign[- ]?in|login|access)\b/i,
        /\byour account (?:has been|was|is|will be)\s+(?:compromised|locked|suspended|accessed|at risk)\b/i,
        /\bsecurity alert\b/i,
        /\bunusual (?:account )?activity\b/i
      ]
    },
    {
      id: 'click_inducement',
      category: 'Links and actions',
      severity: 'medium',
      points: 8,
      title: 'Pushes you to click a link, open an attachment or scan a code',
      why: 'Phishing needs one action from you. Instructions such as "click the link below", "open the attached document" or "scan the QR code" are the delivery mechanism for most attacks.',
      advice: 'Do not click or scan. Navigate to the service yourself using a bookmark, the official app, or an address you type by hand.',
      patterns: [
        /\b(?:click|tap|follow|use|visit)\s+(?:on\s+)?(?:the |this |that )?(?:link|button|url)\s*(?:below|here|to|above|provided)?\b/i,
        /\blog ?in (?:here|below|now|to your account)\b/i,
        /\bsign ?in (?:here|below|now|to your account)\b/i,
        /\b(?:open|view|download|check)\s+(?:the\s+)?(?:attached|attachment|enclosed)\s*(?:document|file|invoice|report|copy)?\b/i,
        /\bscan (?:the )?(?:qr|bar)\s?code\b/i
      ]
    },
    {
      id: 'macro_request',
      category: 'Attachments',
      severity: 'high',
      points: 14,
      title: 'Asks you to enable macros, editing or content',
      why: 'Macros are small programs inside Office documents. Attackers hide malware in them and rely on the recipient clicking "Enable Content" to bypass the security warning that Microsoft built specifically to stop this.',
      advice: 'Do not enable macros or content in a document that arrived by email. If a document genuinely needs macros, ask the sender directly.',
      patterns: [
        /\b(?:enable|allow|turn on|activate)\s+(?:editing|content|macros?|active content|external content)\b/i,
        /\bclick\s+"?enable (?:content|editing|macros?)"?\b/i,
        /\b(?:disable|turn off)\s+(?:protected view|security (?:settings|warnings?))\b/i,
        /\btrust(?:ed)? (?:center|centre)\b/i,
        /\bprotected view\b/i,
        /\bmacros?\b[^.!?\n]{0,30}\b(?:required|enable|disabled|blocked|run)\b/i
      ]
    },
    {
      id: 'delivery_scam',
      category: 'Impersonation',
      severity: 'medium',
      points: 8,
      title: 'Parcel or delivery problem that needs your action',
      why: 'Fake delivery notices ("your parcel is held", "a small fee is due") are one of the most common mass-phishing lures, because almost everyone is waiting for something.',
      advice: 'Track parcels only on the courier\u2019s own website or app, using a tracking number from your original order confirmation.',
      patterns: [
        /\b(?:parcel|package|shipment|delivery|consignment|item)\b[^.!?\n]{0,45}\b(?:held|waiting|awaiting|failed|unable to (?:deliver|be delivered)|undeliverable|on hold|rescheduled|returned to sender|customs|fee|outstanding|tried to deliver)\b/i,
        /\bmissed (?:delivery|parcel|shipment)\b/i,
        /\b(?:reschedule|redeliver|re-?arrange)\b[^.!?\n]{0,35}\b(?:delivery|parcel|shipment)\b/i,
        /\b(?:small|processing|redelivery|handling|customs)\s*fee\b/i
      ]
    },
    {
      id: 'threat_of_financial_loss',
      category: 'Pressure tactics',
      severity: 'medium',
      points: 9,
      title: 'Threatens a penalty, fine, charge or legal consequence',
      why: 'Fines, penalties and legal threats are used to create panic. Genuine authorities send formal documents through reliable channels rather than panic-inducing emails.',
      advice: 'Contact the organisation or authority using contact details from their official website before responding in any way.',
      patterns: [
        /\b(?:penalty|fine|surcharge|legal action|prosecut\w*|court (?:action|proceedings)|arrest|seizure)\b/i,
        /\byou (?:will|may|must)\s+(?:be|face|pay)\b[^.!?\n]{0,30}\b(?:charged|fined|penalised|penalized|prosecuted|liable)/i,
        /\b(?:unpaid|outstanding)\b[^.!?\n]{0,25}\b(?:debt|tax|fine|penalty|balance)\b[^.!?\n]{0,45}\b(?:action|legal|enforcement|court)/i
      ]
    }
  ];

  PEA.rules = { BODY_RULES: BODY_RULES };

  /* ======================================================================
     ATTACHMENT FILENAMES
     ----------------------------------------------------------------------
     extractFilenames() pulls things like "invoice_4821.docm" or
     "Scan_0042.iso" out of the message text. Text that sits inside a URL is
     skipped, so "example.com/page" is never mistaken for a file.
     ====================================================================== */
  function extractFilenames(text, spans) {
    var src = String(text || '');
    var extPattern = PEA.lists.ALL_EXTENSIONS.join('|');
    var re = new RegExp('(?:^|[\\s"\'\\[(<>])([\\w][\\w .\\-()]{0,58}\\.(?:' + extPattern + '))(?![\\w])', 'gi');
    var out = [];
    var m;

    while ((m = re.exec(src)) !== null) {
      var name = m[1].trim().replace(/^[.\-]+/, '');
      if (!name || name.length < 4) { continue; }
      var start = m.index + m[0].indexOf(m[1]);
      var end = start + m[1].length;
      var insideUrl = (spans || []).some(function (s) { return start >= s[0] && end <= s[1]; });
      if (insideUrl) { continue; }
      if (out.indexOf(name.toLowerCase()) === -1) {
        out.push(name.toLowerCase());
      }
    }
    return out;
  }

  function extensionOf(filename) {
    var m = /\.([a-z0-9]+)$/i.exec(String(filename || ''));
    return m ? m[1].toLowerCase() : '';
  }

  function inGroup(ext, group) {
    return (PEA.lists.ATTACHMENT_EXTENSIONS[group] || []).indexOf(ext) !== -1;
  }

  /* ----------------------------------------------------------------------
     Rule metadata for attachment findings, so the interface's scoring table
     can list them alongside the body-language and link rules.
     ---------------------------------------------------------------------- */
  var ATTACHMENT_RULES = {
    executable_attachment: {
      points: 18, severity: 'critical', category: 'Attachments',
      title: 'Executable attachment',
      why: 'This file type is designed to run code. Opening it can install malware immediately, and email filters often miss brand-new variants.',
      advice: 'Do not open it. Delete or report the message, even if you were expecting a document from that person.'
    },
    disk_image_attachment: {
      points: 14, severity: 'high', category: 'Attachments',
      title: 'Disc image attachment (.iso / .img and similar)',
      why: 'Disc images are a favourite way to smuggle executables past email filters, because the dangerous file is hidden inside and Windows may open it without the usual warning.',
      advice: 'Do not mount or open it. Report the message to your IT or security team.'
    },
    macro_attachment: {
      points: 14, severity: 'high', category: 'Attachments',
      title: 'Macro-enabled Office attachment',
      why: 'Formats such as .docm and .xlsm can contain macros. Attackers use them because the document looks ordinary until you click "Enable Content".',
      advice: 'Do not enable content. Ask the sender for a PDF or to share the document through a company system instead.'
    },
    archive_attachment: {
      points: 8, severity: 'medium', category: 'Attachments',
      title: 'Archive attachment (.zip / .rar and similar)',
      why: 'Compressed files bundle dangerous files together and hide them from simple email scanning. Archives are also normal in business use, so this scores moderately.',
      advice: 'Only open an archive you were genuinely expecting, and check what is inside before running anything.'
    },
    risky_attachment: {
      points: 8, severity: 'medium', category: 'Attachments',
      title: 'Attachment type that can carry scripts or content',
      why: 'These formats can contain links, scripts or embedded objects even though they look like ordinary documents or images.',
      advice: 'Treat with caution and verify with the sender through a channel you trust.'
    },
    double_extension: {
      points: 18, severity: 'critical', category: 'Attachments',
      title: 'Double-extension filename (e.g. invoice.pdf.exe)',
      why: 'Windows hides known file extensions by default, so "invoice.pdf.exe" can appear as "invoice.pdf". The real file is still an executable.',
      advice: 'Do not open it. This trick has no innocent explanation.'
    },
    rtl_override_filename: {
      points: 18, severity: 'critical', category: 'Attachments',
      title: 'Filename uses a text-direction trick',
      why: 'An invisible right-to-left override character can reverse part of a filename, so a file ending in .exe is displayed as if it ended in .txt or .doc.',
      advice: 'Do not open it. Treat the message as malicious and report it.'
    },
    unusual_attachment_name: {
      points: 6, severity: 'low', category: 'Attachments',
      title: 'Unusually generic or random attachment name',
      why: 'Names such as "Document_9284.pdf" or "scan0001.pdf" are typical of automated bulk campaigns rather than a person sending you a specific document.',
      advice: 'Consider whether you were expecting a file from this sender at all.'
    }
  };

  function analyseAttachments(filenames) {
    var hits = {};
    filenames.forEach(function (name) {
      var ext = extensionOf(name);
      var added = [];
      var inner = /\.([a-z0-9]+)\.([a-z0-9]+)$/i.exec(name);
      if (inner && ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png', 'txt', 'csv', 'html', 'htm'].indexOf(inner[1]) !== -1
        && ['exe', 'scr', 'js', 'vbs', 'bat', 'cmd', 'pif', 'lnk', 'hta', 'iso', 'zip', 'rar'].indexOf(inner[2]) !== -1) {
        added.push('double_extension');
      }
      if (name.indexOf('\u202e') !== -1 || name.indexOf('\u202d') !== -1) {
        added.push('rtl_override_filename');
      }
      if (added.indexOf('double_extension') === -1) {
        if (inGroup(ext, 'executable')) { added.push('executable_attachment'); }
        else if (inGroup(ext, 'diskImage')) { added.push('disk_image_attachment'); }
        else if (inGroup(ext, 'macroEnabled')) { added.push('macro_attachment'); }
        else if (inGroup(ext, 'archive')) { added.push('archive_attachment'); }
        else if (inGroup(ext, 'unusual')) { added.push('risky_attachment'); }
      }
      if (/\d{3,}/.test(name) || /^(?:document|doc|file|image|scan|attachment|copy|invoice|report)[ _-]?\d*\./i.test(name)) {
        added.push('unusual_attachment_name');
      }
      added.forEach(function (id) {
        if (!hits[id]) { hits[id] = []; }
        if (hits[id].indexOf(name) === -1) { hits[id].push(name); }
      });
    });

    var findings = Object.keys(hits).map(function (id) {
      var meta = ATTACHMENT_RULES[id];
      return {
        id: id,
        source: 'attachment',
        category: meta.category,
        severity: meta.severity,
        points: meta.points,
        title: meta.title,
        why: meta.why,
        advice: meta.advice,
        matches: hits[id].slice(0, 5)
      };
    });

    return { findings: findings, byRule: ATTACHMENT_RULES };
  }

  PEA.rules.extractFilenames = extractFilenames;
  PEA.rules.attachmentRules = ATTACHMENT_RULES;
  PEA.rules.analyseAttachments = analyseAttachments;
  PEA.rules.extensionOf = extensionOf;







}(window.PEA = window.PEA || {}));
