# Phishing Email Analyser

An educational, privacy-first web application that analyses the text of a suspicious email for phishing and social-engineering warning signs, and explains every point of the result.

**It is a triage tool, not a verdict.** It reports warning signs and reasons. It cannot prove that an email is malicious, and it cannot prove that one is genuine.

---

## Privacy: what makes this different

The analysis runs **entirely inside the visitor's browser**.

* No server, no back-end, no database
* No user accounts, no cookies, no localStorage
* No analytics, no telemetry, no tracking
* No AI providers, no paid APIs, no API keys
* **No outbound network requests at all** — no CDNs, no web fonts, no icon packs, no remote images

That last point is stronger than "we don't send your email anywhere": the page is *incapable* of sending anything, because nothing is fetched either. Links inside a pasted email are read as text and never opened, followed or resolved.

You can prove it yourself: press **F12**, open the **Network** tab, clear it, then analyse a message. No new requests appear.

---

## Quick start

No installation, no build step, no dependencies.

1. Open the folder.
2. Double-click **`index.html`**.

That is it. It works from your file system, from a USB stick, or completely offline. If you would rather use a local web address, any static server will do:

```powershell
cd "Phishing Email Analyser"
python -m http.server 8000
# then open http://localhost:8000
```

---

## Documentation

For a full explanation of the logic and the architecture, see **[`docs/HOW-IT-WORKS.md`](docs/HOW-IT-WORKS.md)**. It covers the journey of an email through the engine, the scoring model, why the privacy claim is verifiable, how the risk-responsive theme works, how the tests work, how to add your own rules, a glossary, and an honest list of the project's limits.

---

## What the app does

Paste an email, press **Analyse Email**, and you get:

* **A risk score from 0 to 100**
* **A classification** — No Obvious Warning Signs, Low Risk, Suspicious or High Risk
* **An explanation of every warning sign**, including the exact snippet of text that triggered it
* **Prioritised, practical recommendations**
* **Authoritative context** — sender, Reply-To, Return-Path, SPF/DKIM/DMARC, every link with the flags that apply to it, and attachment filenames
* **Reports** you can copy or save as `.txt` / `.json`, assembled locally

### How the score works

Every rule has a fixed number of points and a written reason. Points are added up and the total is capped at 100. A handful of **combination rules** add extra points when two dangerous things appear together, and each one appears in the results as its own line, so the arithmetic is always visible.

| Score | Classification |
|---|---|
| 0 | No Obvious Warning Signs |
| 1–24 | Low Risk |
| 25–54 | Suspicious |
| 55–100 | High Risk |

The complete list of rules and weights appears in the **Scoring reference** table on the page, generated from the same data the analyser uses so the two cannot drift apart.

---

## Detection coverage

| Area | Examples of what is checked |
|---|---|
| Pressure tactics | Urgency, deadlines, threats of suspension or closure, financial or legal threats, secrecy requests, fake security alerts |
| Credentials | Password requests, one-time / MFA code requests, "verify your account" harvesting language |
| Money | Gift cards, vouchers, wire transfers, cryptocurrency, changed bank details, unexpected invoices |
| Impersonation | Executive and authority impersonation (BEC), brand and support-team impersonation, display-name spoofing, generic greetings, parcel-scam lures |
| Links | Raw IP addresses, shorteners, high-risk suffixes, brand look-alikes, near-miss (typosquat) domains, homoglyph domains, deep subdomain chains, the `@` trick, non-standard ports, heavy encoding, misleading link text |
| Attachments | Executables, disc images (`.iso`, `.img`), macro-enabled Office files, archives, double extensions, invisible text-direction tricks in filenames, generic or random names, macro-enablement requests |
| HTML source | Hidden text, embedded login forms, tracking pixels, obfuscated characters, `javascript:` and `data:` links, mismatched link text |
| Headers | From / Reply-To mismatch, Return-Path mismatch, display-name spoofing, free-mail senders, Message-ID mismatch, spam headers, SPF/DKIM/DMARC failures |

HTML and header analysis only run when you paste them (in most mail clients that is **View source** or **Show original**). Pasting plain body text still works and still scores, but with fewer checks available.

---

## Built-in demonstration emails

Seven fictional messages, available as buttons on the page. None uses a real or working malicious link: every domain ends in the reserved `.example` suffix and every IP address is from the documentation ranges `192.0.2.0/24` and `203.0.113.0/24`.

| Example | Result with the current weights |
|---|---|
| Obvious phishing | High Risk (100, capped) |
| Sophisticated phishing | High Risk (62) |
| Fake Microsoft 365 warning, with failing SPF/DKIM/DMARC | High Risk (100, capped) |
| Fake parcel delivery | Suspicious (50) |
| Fake invoice / BEC | High Risk (68) |
| Malicious attachment (macro spreadsheet plus `.iso`) | High Risk (78) |
| Legitimate email with passing authentication | No Obvious Warning Signs (0) |

---

## Project structure

```
index.html              the page: notices, the analyser, the reference table, the FAQ
css/styles.css          the whole design system (plain CSS, no framework)
js/rules.js             domain/brand/extension lists, shared helpers, body-language rules and weights
js/urls.js              link extraction and link-shape analysis
js/html.js              raw HTML source analysis
js/headers.js           raw header parsing, sender analysis, SPF/DKIM/DMARC
js/recommendations.js   turns findings into a prioritised action list
js/analyser.js          the scoring engine: adds points, applies combination rules, caps at 100
js/samples.js           the seven fictional demonstration emails
js/ui.js                builds the results view (SVG gauge, findings, evidence, reports)
js/app.js               wires the buttons, clipboard, downloads, keyboard shortcuts and toasts
tests/headless-check.js runs the engine in Node with no browser and no dependencies
tests/selftest.html     runs the engine in the browser with a full pass/fail report
```

Scripts are loaded as plain (non-module) scripts in a fixed order, so the site works when opened straight from disk with no web server.

---

## Running the tests

**In a terminal** (optional — needs Node.js):

```powershell
node tests\headless-check.js
```

It prints the score, band and fired rules for each example, then passes or fails each expectation. It also smoke-tests each indicator group, checks that scoring is deterministic, and confirms that empty, whitespace-only and malformed input are handled.

**In a browser:** open `tests/selftest.html` for three tables — engine results, feature coverage (one row per requested indicator) and robustness checks (empty input, junk input, very large input, raw HTML detection, deterministic scoring).

Please re-run one of these after changing any rule or weight.

---

## Customising it

* **Change a weight** — open `js/rules.js`, find the rule and change its `points` value.
* **Add a body-language rule** — copy an existing entry in the `BODY_RULES` array: give it a new `id`, `title`, `why`, `advice`, `severity`, `points` and one or more regular expressions in `patterns`. It then appears automatically in the results, the score arithmetic and the reference table.
* **Add a brand to the look-alike checks** — add an entry to `BRANDS` in `js/rules.js` with its display name, the words that hint at it (`tokens`) and its genuine domains (`domains`).
* **Change the risk bands** — edit the `BANDS` array at the top of `js/analyser.js`, and the band description in the reference table caption in `index.html`.

---


## What it deliberately does not do

* It does not check domain age, reputation or blocklists — that would require contacting the internet
* It does not open, follow or resolve links (a shortened link is reported as hidden, never expanded)
* It does not inspect attachment contents, only filenames
* It does not read images, PDF text or QR codes
* It does not store anything you paste

---

## Safety notes for anyone using it

* **Never click** a suspicious link, open an attachment or scan a QR code just to test it
* **Verify independently** — use the organisation's official app or website, or a phone number you already have, never one from the message
* A low score means "nothing obvious was found", not "this is safe"
* If you already acted on a suspicious message, change the password, enable multi-factor authentication, and contact your bank or IT team immediately

---

## Licence and intent

Built as a learning project for defensive security education. Use it to train your eye, to understand what phishing messages have in common, and to explain risk to other people. It is not a substitute for professional email security controls.


