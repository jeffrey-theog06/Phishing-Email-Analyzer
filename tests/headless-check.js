/* ==========================================================================
   Phishing Email Analyser — tests/headless-check.js
   --------------------------------------------------------------------------
   A small test harness that runs the analyser WITHOUT a browser, so the
   scoring engine can be checked quickly from the terminal:

       node tests\headless-check.js

   It loads the same JavaScript files the web page loads, runs every built-in
   demonstration email through the engine, prints the score and band, and
   checks that each sample lands in the band we expect.

   No dependencies: only Node's built-in `fs` and `vm` modules are used, so
   nothing needs to be installed.
   ========================================================================== */
'use strict';

var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.join(__dirname, '..');

// The browser bits the code expects to exist.
var sandbox = { window: {}, console: console };
sandbox.window.window = sandbox.window;
vm.createContext(sandbox);

// Load order matters and matches index.html exactly.
var FILES = [
  'js/rules.js',
  'js/urls.js',
  'js/html.js',
  'js/headers.js',
  'js/recommendations.js',
  'js/analyser.js',
  'js/samples.js'
];

FILES.forEach(function (rel) {
  var file = path.join(ROOT, rel);
  var code = fs.readFileSync(file, 'utf8');
  vm.runInContext(code, sandbox, { filename: rel });
});

var PEA = sandbox.window.PEA;

// What we expect each demonstration email to score.
var EXPECT = {
  'obvious': { band: 'high', min: 70 },
  'sophisticated': { band: 'high', min: 55 },
  'm365': { band: 'high', min: 80 },
  'parcel': { band: 'medium', min: 25, max: 54 },
  'invoice-bec': { band: 'high', min: 55 },
  'attachment': { band: 'high', min: 70 },
  'legitimate': { band: 'clear', min: 0, max: 0 }
};

var failures = 0;
var totalRules = PEA.analyser.allRuleMetadata().length;

console.log('');
console.log('Phishing Email Analyser — engine check');
console.log('Rules and weights registered: ' + totalRules);
console.log('Bands: ' + PEA.analyser.BANDS.map(function (b) {
  return b.label + ' (' + b.min + '-' + b.max + ')';
}).join('  |  '));
console.log('');

PEA.samples.all.forEach(function (sample) {
  var result = PEA.analyser.analyse(sample.text);
  var expect = EXPECT[sample.id] || {};
  var problems = [];

  if (expect.band && result.band.id !== expect.band) {
    problems.push('expected band "' + expect.band + '", got "' + result.band.id + '"');
  }
  if (typeof expect.min === 'number' && result.score < expect.min) {
    problems.push('expected score >= ' + expect.min + ', got ' + result.score);
  }
  if (typeof expect.max === 'number' && result.score > expect.max) {
    problems.push('expected score <= ' + expect.max + ', got ' + result.score);
  }
  if (result.score < 0 || result.score > 100) {
    problems.push('score outside 0-100');
  }

  var ok = problems.length === 0;
  if (!ok) { failures++; }

  console.log((ok ? '  PASS  ' : '  FAIL  ') + sample.id.padEnd(14) +
    'score ' + String(result.score).padStart(3) + '  ' + result.band.label);

  var fired = result.findings.filter(function (f) { return f.points > 0; })
    .map(function (f) { return f.id + '+' + f.points; });
  console.log('          fired: ' + (fired.length ? fired.join(', ') : '(none)'));
  console.log('          urls: ' + result.detection.urlCount +
    ', files: ' + result.detection.fileCount +
    ', headers: ' + (result.detection.headersFound ? 'yes' : 'no') +
    ', html: ' + (result.detection.htmlFound ? 'yes' : 'no'));
  if (problems.length) {
    console.log('          PROBLEMS: ' + problems.join('; '));
  }
  console.log('');
});

// ---------------------------------------------------------------------------
// Indicator smoke tests: one short synthetic message per indicator group, to
// confirm the rule really does fire. These are analysis-only strings that are
// never opened, resolved or contacted in any way.
// ---------------------------------------------------------------------------
var SMOKE = [
  { name: 'urgency language', text: 'This is urgent, you must act immediately.', expect: ['urgency_pressure'] },
  { name: 'account suspension threat', text: 'Your account will be suspended within 24 hours unless you act.', expect: ['account_threat'] },
  { name: 'password request', text: 'Please confirm your password to continue.', expect: ['password_request'] },
  { name: 'MFA code request', text: 'Share the verification code with our support team.', expect: ['mfa_code_request'] },
  { name: 'gift card request', text: 'Please buy gift cards and send me the codes.', expect: ['unusual_payment'] },
  { name: 'bank detail change', text: 'Our bank details have changed, please update your remittance instructions.', expect: ['bank_details_change'] },
  { name: 'unexpected invoice', text: 'Your overdue invoice is attached, please pay the attached invoice.', expect: ['unexpected_invoice'] },
  { name: 'impersonation', text: 'This is the IT support team and we need your help.', expect: ['generic_impersonation', 'bec_authority'] },
  { name: 'generic greeting', text: 'Dear Customer, please review the following.', expect: ['generic_greeting'] },
  { name: 'credential harvesting', text: 'Click the link below to verify your account now.', expect: ['credential_harvesting'] },
  { name: 'click inducement', text: 'Please click the link below to continue.', expect: ['click_inducement'] },
  { name: 'macro request', text: 'Open the document then click "Enable Content" to view it.', expect: ['macro_request'] },
  { name: 'executable attachment', text: 'See the attached file invoice-2025.exe for details.', expect: ['executable_attachment'] },
  { name: 'disc image attachment', text: 'The enclosed remittance scan.iso holds the copy.', expect: ['disk_image_attachment'] },
  { name: 'macro enabled attachment', text: 'Please open payslip-final.xlsm and check the figures.', expect: ['macro_attachment'] },
  { name: 'raw IP link', text: 'Log in at http://203.0.113.9/login to continue.', expect: ['ip_address_url'] },
  { name: 'shortened link', text: 'Confirm here: https://bit.ly/3xYzAbC', expect: ['shortened_url'] },
  { name: 'high risk suffix', text: 'Visit https://q7z2-check-nonexistent.xyz/login now.', expect: ['risky_tld'] },
  { name: 'near-miss domain', text: 'Sign in at https://paypa1.example/login to continue.', expect: ['typosquat_domain'] },
  { name: 'look-alike characters', text: 'Sign in at https://\u0440\u0430\u0443\u0440\u0430\u043b.example/login', expect: ['homoglyph_domain'] },
  { name: 'brand in wrong domain', text: 'Sign in at https://microsoft-support-portal.example/login', expect: ['brand_lookalike_domain'] },
  { name: 'no HTTPS', text: 'Open http://plain.http-check.example/page', expect: ['no_https'] },
  {
    name: 'SPF, DKIM and DMARC failures',
    text: 'From: "Bank Alerts" <alerts@bank-notice.example>\n' +
      'Reply-To: <reply@other-mail.example>\n' +
      'Subject: Alert\n' +
      'Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail\n' +
      '\nNothing much to see in the body.',
    expect: ['spf_fail', 'dkim_fail', 'dmarc_fail', 'reply_to_mismatch']
  }
];

console.log('Indicator smoke tests');
var smokeFailures = 0;
SMOKE.forEach(function (item) {
  var result = PEA.analyser.analyse(item.text);
  var firedIds = result.findings.map(function (f) { return f.id; });
  var missing = item.expect.filter(function (id) { return firedIds.indexOf(id) === -1; });
  if (missing.length) {
    smokeFailures++;
    failures++;
    console.log('  FAIL  ' + item.name + ' \u2014 did not fire: ' + missing.join(', '));
  } else {
    console.log('  PASS  ' + item.name + ' \u2014 ' + item.expect.join(', '));
  }
});
console.log('');

// ---------------------------------------------------------------------------
// UI smoke test: load ui.js and app.js against a minimal stand-in DOM, then
// click "Analyse Email" the way a visitor would. This exercises the rendering
// code and the event wiring without needing a real browser.
// ---------------------------------------------------------------------------
function makeStubEl(tag) {
  var classes = {};
  var node = {
    tagName: tag, className: '', textContent: '', value: '', type: '', href: '', download: '',
    style: {}, dataset: {}, childNodes: [], attributes: {}, listeners: {}, parentNode: null,
    setAttribute: function (k, v) { node.attributes[k] = String(v); },
    removeAttribute: function (k) { delete node.attributes[k]; },
    getAttribute: function (k) { return node.attributes[k]; },
    appendChild: function (c) { node.childNodes.push(c); if (c) { c.parentNode = node; } return c; },
    removeChild: function (c) { var i = node.childNodes.indexOf(c); if (i >= 0) { node.childNodes.splice(i, 1); } return c; },
    addEventListener: function (k, fn) { (node.listeners[k] = node.listeners[k] || []).push(fn); },
    fire: function (k, ev) { (node.listeners[k] || []).forEach(function (fn) { fn(ev || {}); }); },
    scrollIntoView: function () {}, click: function () {}, focus: function () {}, remove: function () {},
    classList: {
      add: function (c) { classes[c] = true; },
      remove: function (c) { delete classes[c]; },
      contains: function (c) { return !!classes[c]; },
      toString: function () { return Object.keys(classes).join(' '); }
    },
    querySelector: function () { return null; }, querySelectorAll: function () { return []; }
  };
  Object.defineProperty(node, 'firstChild', {
    get: function () { return node.childNodes.length ? node.childNodes[0] : null; }
  });
  return node;
}

function collectText(node, out) {
  out = out || [];
  if (!node) { return out; }
  if (node.textContent) { out.push(node.textContent); }
  node.childNodes.forEach(function (c) { collectText(c, out); });
  return out;
}

function runUiSmokeTest() {
  var problems = [];
  var registry = {};

  var fakeDoc = {
    readyState: 'complete',
    body: makeStubEl('body'),
    documentElement: makeStubEl('html'),
    createElement: makeStubEl,
    createElementNS: function (ns, tag) { return makeStubEl(tag); },
    createTextNode: function (t) { var n = makeStubEl('#text'); n.textContent = String(t); return n; },
    getElementById: function (id) { return registry[id] || (registry[id] = makeStubEl('div')); },
    querySelector: function () { return makeStubEl('div'); },
    querySelectorAll: function () { return []; },
    addEventListener: function () {}
  };

  var sandbox2 = {
    console: console,
    document: fakeDoc,
    navigator: {},
    Blob: function () {},
    URL: { createObjectURL: function () { return 'blob:local'; }, revokeObjectURL: function () {} },
    performance: { now: function () { return 0; } },
    setTimeout: function () { return 0; },
    clearTimeout: function () {},
    Date: Date, JSON: JSON, Math: Math, Object: Object, Array: Array, String: String, Number: Number,
    RegExp: RegExp, Boolean: Boolean, Error: Error, isNaN: isNaN, parseInt: parseInt, parseFloat: parseFloat
  };
  sandbox2.window = sandbox2;
  vm.createContext(sandbox2);

  FILES.concat(['js/ui.js', 'js/app.js']).forEach(function (rel) {
    var code = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    vm.runInContext(code, sandbox2, { filename: rel });
  });

  var PEA2 = sandbox2.window.PEA;

  // Did app.js initialise the page?
  var chipCount = registry['sample-chips'] ? registry['sample-chips'].childNodes.length : -1;
  if (chipCount !== PEA2.samples.all.length) {
    problems.push('expected ' + PEA2.samples.all.length + ' example buttons, got ' + chipCount);
  }

  var expectedRows = PEA2.analyser.allRuleMetadata().length;
  var rowCount = registry['reference-body'] ? registry['reference-body'].childNodes.length : -1;
  if (rowCount !== expectedRows) {
    problems.push('reference table has ' + rowCount + ' rows, expected ' + expectedRows);
  }

  // Click "Analyse Email" with a real example in the box.
  registry['email-input'].value = PEA2.samples.byId('m365').text;
  var analyseBtn = registry['analyse-btn'];
  if (!analyseBtn || !(analyseBtn.listeners.click || []).length) {
    problems.push('the Analyse Email button has no click handler');
  } else {
    try {
      analyseBtn.fire('click');
    } catch (err) {
      problems.push('clicking Analyse Email threw: ' + err.message);
    }
  }

  // The whole page theme must follow the verdict.
  var risk = fakeDoc.documentElement.attributes['data-risk'];
  if (risk !== 'high') {
    problems.push('the page theme did not switch to high risk (data-risk="' + risk + '")');
  }
  if (!fakeDoc.body.classList.contains('has-result')) {
    problems.push('the body did not receive the has-result class, so the alarm chrome stays hidden');
  }
  var announced = registry['verdict-announcer'] ? registry['verdict-announcer'].textContent : '';
  if (announced.indexOf('High Risk') === -1) {
    problems.push('the screen-reader announcement does not state the verdict');
  }
  var hudText = collectText(registry['hud']).join(' | ');
  if (hudText.indexOf('High Risk') === -1 || hudText.indexOf('score 100/100') === -1) {
    problems.push('the status bar does not show the verdict and score');
  }

  var rendered = collectText(registry['results']).join(' | ');
  if (rendered.indexOf('High Risk') === -1) {
    problems.push('the rendered result does not mention the risk band');
  }
  if (rendered.indexOf('What to do next') === -1) {
    problems.push('the rendered result has no recommendations section');
  }
  if (rendered.indexOf('What this tool cannot tell you') === -1) {
    problems.push('the rendered result has no limits section');
  }
  if (rendered.indexOf('score describes warning signs') === -1) {
    problems.push('the rendered result is missing the "not a verdict" reminder');
  }

  // Reports
  var result = PEA2.analyser.analyse(PEA2.samples.byId('m365').text);
  var asText = PEA2.ui.toPlainText(result);
  if (asText.indexOf('RISK SCORE') === -1 || asText.indexOf('WHAT TO DO NEXT') === -1) {
    problems.push('the text report is missing key sections');
  }
  try {
    var parsed = JSON.parse(PEA2.ui.toJson(result));
    if (parsed.score !== result.score) { problems.push('the JSON report score does not match the result'); }
  } catch (err) {
    problems.push('the JSON report is not valid JSON: ' + err.message);
  }

  // The Clear button should reset the panel.
  registry['clear-btn'].fire('click');
  if (collectText(registry['results']).join(' | ').indexOf('Ready when you are') === -1) {
    problems.push('the Clear button did not reset the results panel');
  }

  return problems;
}

console.log('UI smoke test (stand-in DOM)');
var uiProblems = runUiSmokeTest();
if (uiProblems.length) {
  uiProblems.forEach(function (p) { console.log('  FAIL  ' + p); });
  failures += uiProblems.length;
} else {
  console.log('  PASS  page initialises, renders a result, builds both reports and clears');
}
console.log('');

// Sanity check: the same input twice must give the same score.
var repeatA = PEA.analyser.analyse(PEA.samples.byId('m365').text).score;
var repeatB = PEA.analyser.analyse(PEA.samples.byId('m365').text).score;
if (repeatA !== repeatB) { failures++; console.log('  FAIL  scoring is not deterministic'); }

// Sanity check: empty input must be handled without throwing.
var empty = PEA.analyser.analyse('');
if (empty.score !== 0 || empty.meta.empty !== true) {
  failures++; console.log('  FAIL  empty input handled incorrectly');
}

// Sanity check: nonsense input must not crash.
var junk = PEA.analyser.analyse('<><><> \\ \\ %%% ###');
if (typeof junk.score !== 'number') { failures++; console.log('  FAIL  junk input handled incorrectly'); }

console.log(failures === 0
  ? 'All checks passed.'
  : failures + ' check(s) failed.');
console.log('');

process.exit(failures === 0 ? 0 : 1);
