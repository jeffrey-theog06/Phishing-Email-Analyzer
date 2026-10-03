/* ==========================================================================
   Phishing Email Analyser — js/urls.js
   --------------------------------------------------------------------------
   Finds links in the pasted text and inspects the *shape* of each one.

   IMPORTANT PRIVACY NOTE: this module never contacts a URL. It does not resolve
   it, fetch it, follow redirects, query whois or ask a reputation service.
   Shortened links are therefore reported as "destination hidden" rather than
   resolved. Everything below is pure string analysis inside the browser.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var U = PEA.util;
  var L = PEA.lists;

  // Top-level domains used when spotting links written without "http://"
  // (people often paste "login.microsoft-verify.example" on its own).
  var COMMON_TLDS = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'io',
    'co', 'me', 'tv', 'cc', 'app', 'dev', 'ly', 'to', 'ai', 'us', 'uk', 'ca', 'au', 'de',
    'fr', 'jp', 'cn', 'ru', 'br', 'in', 'nl', 'it', 'es', 'se', 'no', 'eu', 'ch', 'pl', 'be',
    'at', 'dk', 'fi', 'gr', 'pt', 'ie', 'hk', 'sg', 'my', 'ph', 'th', 'vn', 'id', 'pk', 'ng',
    'ke', 'eg', 'sa', 'tr', 'ar', 'cl', 'pe', 'mx', 'za', 'nz', 'cz', 'ro', 'hu', 'sk', 'bg'];

  var SCHEME_RE = /\b(?:hxxps?|https?|ftps?)\s*:\s*\/\/[^\s<>"'`]+/gi;

  function allTlds() {
    var out = COMMON_TLDS.concat(L.SUSPICIOUS_TLDS);
    return out.filter(function (v, i) { return out.indexOf(v) === i; }).join('|');
  }

  var BARE_HOST_RE = new RegExp(
    '\\b(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\\.)+(?:' + allTlds() + ')\\b',
    'gi'
  );

  // Trim punctuation that is almost never part of a real URL.
  function trimUrl(raw) {
    return String(raw).replace(/[.,;:!?'"\)\]\}>]+$/, '');
  }

  function parseUrl(candidate) {
    var normalized = U.normalizeDefanged(candidate);
    var rest = normalized.replace(/^[a-z]+:\/\//i, '');
    var schemeMatch = /^([a-z]+):\/\//i.exec(normalized);
    var scheme = schemeMatch ? schemeMatch[1].toLowerCase() : '';

    // Anything before an "@" is user-info: a classic trick to hide the real host.
    var userinfo = '';
    var atIndex = rest.indexOf('@');
    var hostPart = rest;
    if (atIndex !== -1) {
      userinfo = rest.slice(0, atIndex);
      hostPart = rest.slice(atIndex + 1);
    }

    var slash = hostPart.search(/[\/?#]/);
    var authority = slash === -1 ? hostPart : hostPart.slice(0, slash);
    var tail = slash === -1 ? '' : hostPart.slice(slash);

    var port = '';
    var portMatch = /:(\d{1,5})$/.exec(authority);
    if (portMatch) {
      port = portMatch[1];
      authority = authority.slice(0, authority.length - portMatch[0].length);
    }

    var host = authority.toLowerCase().replace(/\.$/, '');
    return {
      raw: candidate,
      normalized: normalized,
      scheme: scheme || 'http',
      host: host,
      port: port,
      userinfo: userinfo,
      tail: tail
    };
  }

  /* ----------------------------------------------------------------------
     extract(text) -> { urls: [parsedUrl], spans: [[start,end]] }
     `spans` is used so that text inside a URL is not counted twice when we
     look for filenames and domains elsewhere in the message.
     ---------------------------------------------------------------------- */
  function extract(text) {
    var src = String(text || '');
    var urls = [];
    var spans = [];
    var seen = {};
    var m;

    SCHEME_RE.lastIndex = 0;
    while ((m = SCHEME_RE.exec(src)) !== null) {
      var raw = trimUrl(m[0]);
      if (!raw) { continue; }
      var parsed = parseUrl(raw);
      if (!parsed.host) { continue; }
      var key = parsed.normalized.toLowerCase();
      if (seen[key]) { continue; }
      seen[key] = true;
      parsed.start = m.index;
      parsed.end = m.index + raw.length;
      parsed.defanged = parsed.normalized !== raw;
      parsed.bare = false;
      urls.push(parsed);
      spans.push([parsed.start, parsed.end]);
    }

    BARE_HOST_RE.lastIndex = 0;
    while ((m = BARE_HOST_RE.exec(src)) !== null) {
      var start = m.index;
      var end = start + m[0].length;
      // Skip anything already inside a URL we captured.
      var inside = spans.some(function (s) { return start >= s[0] && end <= s[1]; });
      if (inside) { continue; }
      // Skip things that are really email addresses (word@domain).
      var before = src.charAt(start - 1);
      if (before === '@' || before === '/') { continue; }
      var hostOnly = m[0].toLowerCase();
      if (seen['http://' + hostOnly]) { continue; }
      seen['http://' + hostOnly] = true;
      urls.push({
        raw: m[0], normalized: 'http://' + hostOnly, scheme: '(none)',
        host: hostOnly, port: '', userinfo: '', tail: '',
        start: start, end: end, defanged: false, bare: true
      });
      spans.push([start, end]);
    }

    return { urls: urls, spans: spans };
  }

  /* ----------------------------------------------------------------------
     Brand helpers
     ---------------------------------------------------------------------- */
  // Generic words that should never be treated as a look-alike of a brand.
  // Without this list, subdomains such as "secure.example" could produce
  // nonsense matches against brand names.
  var STOPWORDS = ['example', 'sample', 'test', 'demo', 'local', 'localhost', 'invalid',
    'mail', 'email', 'smtp', 'webmail', 'portal', 'login', 'signin', 'account', 'secure',
    'security', 'verify', 'verification', 'update', 'support', 'service', 'services',
    'tracking', 'delivery', 'parcel', 'invoice', 'billing', 'notice', 'alert', 'message'];

  // Break a hostname into candidate "words": whole labels plus their parts.
  // login.microsoft-verify.example -> [login, microsoft-verify, microsoft, verify, example]
  function labelTokens(host) {
    var out = [];
    String(host || '').toLowerCase().split('.').forEach(function (label) {
      if (!label) { return; }
      if (out.indexOf(label) === -1) { out.push(label); }
      label.split(/[-_]+/).forEach(function (part) {
        if (part && out.indexOf(part) === -1) { out.push(part); }
      });
    });
    return out;
  }

  function matchesBrandToken(host, token) {
    var tokens = labelTokens(host);
    // Short tokens such as "ups" or "irs" must be a whole label or part,
    // otherwise words like "groups.example" would produce false alarms.
    if (token.length < 5) {
      return tokens.indexOf(token) !== -1;
    }
    return tokens.some(function (lab) { return lab.indexOf(token) !== -1; });
  }

  function brandForHost(host) {
    var found = null;
    L.BRANDS.forEach(function (brand) {
      if (found) { return; }
      if (brand.tokens.some(function (t) { return matchesBrandToken(host, t); })) {
        found = brand;
      }
    });
    return found;
  }

  function isOfficialDomain(host, brand) {
    return brand.domains.indexOf(U.registrableDomain(host)) !== -1;
  }

  /* ----------------------------------------------------------------------
     Look-alike (typosquat) detection.
     Each word-like part of the hostname is compared with each brand's real
     domain name. A difference of one or two characters counts as a
     near-miss: micros0ft, arnazon, paypa1, barckays and so on.
     ---------------------------------------------------------------------- */
  function typosquatBrand(host) {
    if (isOfficialHostAnyBrand(host)) { return null; }

    var candidates = labelTokens(host).filter(function (c) {
      return c.length >= 5 && STOPWORDS.indexOf(c) === -1;
    });
    var flat = U.domainCore(host).replace(/[-_]/g, '');
    if (flat.length >= 5 && STOPWORDS.indexOf(flat) === -1 && candidates.indexOf(flat) === -1) {
      candidates.push(flat);
    }
    if (!candidates.length) { return null; }

    var hit = null;
    L.BRANDS.forEach(function (brand) {
      if (hit) { return; }
      brand.domains.forEach(function (d) {
        if (hit) { return; }
        var target = U.domainCore(d);
        if (!target || target.length < 5) { return; }
        candidates.forEach(function (c) {
          if (hit) { return; }
          var dist = U.editDistance(c, target);
          if (dist > 0 && dist <= 2) {
            hit = { brand: brand, target: d, distance: dist };
          }
        });
      });
    });
    return hit;
  }

  function isOfficialHostAnyBrand(host) {
    var reg = U.registrableDomain(host);
    return L.BRANDS.some(function (b) { return b.domains.indexOf(reg) !== -1; });
  }

  /* ----------------------------------------------------------------------
     flagUrl(entry) -> [ {id, tone, label, note} ]
     Produces the short labels shown next to each link, and the raw material
     that analyse() turns into scored findings.
     ---------------------------------------------------------------------- */
  function flagUrl(entry) {
    var host = entry.host;
    var flags = [];
    var tld = U.lastTld(host);
    var reg = U.registrableDomain(host);
    var brand = brandForHost(host);
    var typo;

    if (U.isIpAddressHost(host)) {
      flags.push({ id: 'ip_address_url', tone: 'bad', label: 'Raw IP address', note: 'A link that names a raw IP address instead of a domain name rarely belongs to a legitimate business.' });
    }
    if (L.URL_SHORTENERS.indexOf(reg) !== -1) {
      flags.push({ id: 'shortened_url', tone: 'warn', label: 'Shortened link', note: 'The real destination is hidden behind a shortening service. This tool will not follow it.' });
    }
    if (L.SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
      flags.push({ id: 'risky_tld', tone: 'warn', label: 'High-risk suffix (.' + tld + ')', note: 'This suffix is cheap or free to register and is used heavily in short-lived phishing campaigns.' });
    }
    if (brand && !isOfficialDomain(host, brand)) {
      flags.push({ id: 'brand_lookalike_domain', tone: 'bad', label: 'Mentions ' + brand.name + ' but is not their domain', note: 'The brand name appears in the address, but the domain belongs to someone else. Official ' + brand.name + ' mail comes from ' + brand.domains.join(', ') + '.' });
    }
    typo = typosquatBrand(host);
    if (typo) {
      flags.push({ id: 'typosquat_domain', tone: 'bad', label: 'Near-miss of ' + typo.brand.name + ' (' + typo.target + ')', note: 'The domain is only ' + typo.distance + ' character(s) away from ' + typo.target + '. That is a classic look-alike address.' });
    }
    if (U.hasNonAscii(host) || host.indexOf('xn--') !== -1) {
      flags.push({ id: 'homoglyph_domain', tone: 'bad', label: 'Look-alike or non-English characters', note: 'The domain uses characters that resemble ordinary letters, or a punycode form, to imitate a known brand.' });
    }
    if (host.split('.').length >= 4) {
      flags.push({ id: 'many_subdomains', tone: 'warn', label: 'Deep subdomain chain', note: 'Long chains of subdomains push the real domain out of sight, especially on a phone screen.' });
    }
    if (entry.userinfo) {
      flags.push({ id: 'at_sign_in_url', tone: 'bad', label: 'Contains "@" before the host', note: 'Text before an "@" is ignored by the browser, so a link can look respectable while sending you somewhere completely different.' });
    }
    if (entry.scheme === 'http') {
      flags.push({ id: 'no_https', tone: 'warn', label: 'Not HTTPS', note: 'The link is not encrypted. Login and payment pages should always use HTTPS.' });
    }
    if (entry.port && entry.port !== '80' && entry.port !== '443') {
      flags.push({ id: 'nonstandard_port', tone: 'warn', label: 'Non-standard port :' + entry.port, note: 'Ordinary websites do not ask you to connect on an unusual port number.' });
    }
    if ((String(entry.normalized).match(/%[0-9a-f]{2}/gi) || []).length >= 3) {
      flags.push({ id: 'encoded_url_chars', tone: 'warn', label: 'Heavily encoded characters', note: 'Long runs of percent-encoded characters can disguise what a link really says.' });
    }
    if (entry.defanged) {
      flags.push({ id: 'defanged_link', tone: 'ok', label: 'Written in defanged form (hxxp / [.])', note: 'The text was deliberately broken so it cannot be clicked. It has been inspected as plain text only.' });
    }
    if (entry.bare) {
      flags.push({ id: 'bare_domain', tone: 'ok', label: 'Domain written without a protocol', note: 'This is a bare domain name rather than a full clickable link.' });
    }
    return flags;
  }

  /* ----------------------------------------------------------------------
     The scoring weights for link findings. Points are awarded once per rule
     type no matter how many links triggered it, so a message full of bad
     links cannot inflate the score.
     ---------------------------------------------------------------------- */
  var WEIGHTS = {
    ip_address_url: {
      points: 12, severity: 'high', title: 'Link uses a raw IP address',
      why: 'Legitimate services publish real domain names. A link that points at a bare numeric address is a strong indicator of throw-away infrastructure.',
      advice: 'Do not visit the address. If the message claims to be from a company, contact them through their official site instead.'
    },
    shortened_url: {
      points: 8, severity: 'medium', title: 'Shortened link hides its destination',
      why: 'A shortening service means you cannot see where you would be sent. Attackers use this to disguise malicious destinations, and legitimate senders rarely need it.',
      advice: 'Do not click it. If the message matters, ask the sender for the full address or find the page yourself.'
    },
    risky_tld: {
      points: 10, severity: 'medium', title: 'Link uses a high-risk domain suffix',
      why: 'Some domain suffixes are free or very cheap and are recycled constantly by phishing campaigns, so their presence raises suspicion. It is a supporting clue rather than proof.',
      advice: 'Read the whole address carefully and ask whether you would expect this organisation to use that kind of domain at all.'
    },
    brand_lookalike_domain: {
      points: 12, severity: 'high', title: 'Link uses a brand name it does not own',
      why: 'The address mentions a well-known brand but is registered under a different domain. This is the standard way fake login pages are hosted.',
      advice: 'Never sign in through this link. Open the service from your own bookmark, the official app, or an address you type by hand.'
    },
    typosquat_domain: {
      points: 12, severity: 'high', title: 'Link is a near-miss copy of a real domain',
      why: 'The domain differs by only a character or two from a genuine one (an extra hyphen, or a substituted letter such as a zero for an "o"). This is deliberate and targets people who skim.',
      advice: 'Never sign in through this link. Compare the address letter by letter with the organisation\u2019s published domain.'
    },
    homoglyph_domain: {
      points: 10, severity: 'high', title: 'Link uses look-alike characters in the domain',
      why: 'Characters from other alphabets can look identical to Latin letters, letting an attacker register a visually convincing fake domain.',
      advice: 'Do not trust a link whose address you cannot read character by character. Reach the organisation through a route you control.'
    },
    many_subdomains: {
      points: 6, severity: 'medium', title: 'Link buries the real domain behind many subdomains',
      why: 'Long subdomain chains push the genuine domain off the visible part of the address bar, especially on a phone.',
      advice: 'Read the address from the right-hand side to find the domain that actually owns the page.'
    },
    at_sign_in_url: {
      points: 12, severity: 'high', title: 'Link uses the "@" trick to look trustworthy',
      why: 'Everything before an "@" in a web address is ignored by the browser, so a link can display a familiar name while sending you somewhere completely different.',
      advice: 'Do not click it. Treat the link as hostile and verify the message another way.'
    },
    no_https: {
      points: 5, severity: 'low', title: 'Link does not use HTTPS',
      why: 'Unencrypted links are increasingly rare for real services and slightly increase the risk of interception or tampering. Many legitimate marketing links still use plain HTTP, so this scores low.',
      advice: 'Be cautious about entering any information on an unencrypted page.'
    },
    nonstandard_port: {
      points: 6, severity: 'medium', title: 'Link uses an unusual port number',
      why: 'Web addresses normally use standard ports, which stay hidden. An explicit unusual port suggests a self-hosted or temporary endpoint.',
      advice: 'Do not visit it; report the message instead.'
    },
    encoded_url_chars: {
      points: 6, severity: 'medium', title: 'Link contains heavily encoded characters',
      why: 'Percent-encoding can hide the true path or parameters of a link so that it looks harmless when skimmed.',
      advice: 'Do not click it. Ask the sender for a plain description of the page instead.'
    }
  };

  /* ----------------------------------------------------------------------
     analyse(urls) -> { findings, details }
     `details` powers the "links found" panel, `findings` feeds the score.
     ---------------------------------------------------------------------- */
  function analyse(urls) {
    var details = [];
    var byRule = {};

    (urls || []).forEach(function (entry) {
      var flags = flagUrl(entry);
      details.push({
        url: entry.normalized,
        display: entry.raw,
        host: entry.host,
        registrable: U.registrableDomain(entry.host),
        bare: entry.bare,
        scheme: entry.scheme,
        flags: flags
      });
      flags.forEach(function (f) {
        if (!WEIGHTS[f.id]) { return; }
        if (!byRule[f.id]) {
          byRule[f.id] = { id: f.id, meta: WEIGHTS[f.id], matches: [], notes: [] };
        }
        if (byRule[f.id].matches.length < 4) { byRule[f.id].matches.push(entry.raw); }
        if (byRule[f.id].notes.indexOf(f.note) === -1) { byRule[f.id].notes.push(f.note); }
      });
    });

    var findings = Object.keys(byRule).map(function (id) {
      var r = byRule[id];
      return {
        id: id,
        source: 'url',
        category: 'Links and actions',
        severity: r.meta.severity,
        points: r.meta.points,
        title: r.meta.title,
        why: r.meta.why,
        advice: r.meta.advice,
        matches: r.matches.slice(),
        extra: r.notes.slice(0, 2).join(' ')
      };
    });

    return { findings: findings, details: details };
  }

  PEA.urls = {
    extract: extract,
    analyse: analyse,
    parseUrl: parseUrl,
    weights: WEIGHTS,
    COMMON_TLDS: COMMON_TLDS
  };
}(window.PEA = window.PEA || {}));



