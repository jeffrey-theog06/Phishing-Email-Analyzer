# 🎣 Phishing Email Analyzer

[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![HTML5](https://img.shields.io/badge/HTML5-Static%20App-E34F26?style=for-the-badge&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-Dark%20Theme-1572B6?style=for-the-badge&logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)
[![Privacy First](https://img.shields.io/badge/Privacy-100%25%20Client--Side-4CAF50?style=for-the-badge&logo=shieldsdotio&logoColor=white)](https://github.com/jeffrey-theog06/Phishing-Email-Analyzer)
[![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=for-the-badge)](https://github.com/jeffrey-theog06/Phishing-Email-Analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

> **A privacy-first, fully browser-based phishing email triage tool that scores suspicious emails from 0–100 using a transparent rule engine — no server, no API keys, no tracking, no outbound requests.**

---

## 🔒 Privacy: What Makes This Different

The entire analysis runs **inside the visitor's browser** — nothing ever leaves the page.

- No server, no back-end, no database
- No user accounts, no cookies, no localStorage
- No analytics, no telemetry, no tracking
- No AI providers, no paid APIs, no API keys
- **No outbound network requests at all** — no CDNs, no web fonts, no icon packs, no remote images

That last point is stronger than "we don't send your email anywhere": the page is *incapable* of sending anything, because nothing is fetched either. Links inside a pasted email are read as text and never opened, followed, or resolved.

You can verify this yourself: press **F12**, open the **Network** tab, clear it, then analyse a message. No new requests appear.

---

## 🧭 Quick Navigation

- [What the App Does](#-what-the-app-does)
- [Detection Coverage](#-detection-coverage)
- [Project Structure](#-project-structure)
- [Built-in Demo Emails](#-built-in-demonstration-emails)
- [Running the Tests](#-running-the-tests)
- [Customising the Rules](#-customising-it)
- [Author](#-author)

---

## 🚀 Quick Start

No installation, no build step, no dependencies.

1. Clone or download the repository.
2. Double-click **`index.html`**.

That's it. It works directly from your file system, from a USB stick, or completely offline. For a local web address:

```powershell
cd "Phishing Email Analyzer"
python -m http.server 8000
# then open http://localhost:8000
```

---

## 🔍 What the App Does

Paste an email (body, headers, or raw HTML source), press **Analyse Email**, and you get:

- **A risk score from 0 to 100**
- **A classification** — No Obvious Warning Signs / Low Risk / Suspicious / High Risk
- **An explanation of every warning sign**, including the exact snippet of text that triggered it
- **Prioritised, practical recommendations**
- **Authoritative context** — sender, Reply-To, Return-Path, SPF/DKIM/DMARC, every link with applicable flags, and attachment filenames
- **Exportable reports** — copy or save as `.txt` / `.json`, assembled entirely locally

### How the Score Works

Every rule carries a fixed point value and a written reason. Points accumulate and are capped at 100. A set of **combination rules** add extra points when two dangerous signals appear together, and each combination shows up as its own line — so the arithmetic is always fully visible.

| Score | Classification |
| :---: | :--- |
| 0 | No Obvious Warning Signs |
| 1 – 24 | Low Risk |
| 25 – 54 | Suspicious |
| 55 – 100 | High Risk |

The complete rule list and weights are rendered as a **Scoring Reference** table directly on the page, generated from the same data the analyser uses — so the two can never drift apart.

---

## 🛡️ Detection Coverage

| Area | Examples of What Is Checked |
| :--- | :--- |
| **Pressure Tactics** | Urgency, deadlines, threats of suspension or closure, financial/legal threats, secrecy requests, fake security alerts |
| **Credential Harvesting** | Password requests, one-time/MFA code requests, "verify your account" language |
| **Money & Fraud** | Gift cards, vouchers, wire transfers, cryptocurrency, changed bank details, unexpected invoices |
| **Impersonation** | Executive/authority impersonation (BEC), brand & support-team spoofing, display-name spoofing, generic greetings, parcel-scam lures |
| **Malicious Links** | Raw IP addresses, URL shorteners, high-risk TLDs, brand look-alikes, typosquat domains, homoglyph domains, deep subdomain chains, the `@` trick, non-standard ports, heavy encoding, misleading link text |
| **Dangerous Attachments** | Executables, disc images (`.iso`, `.img`), macro-enabled Office files, archives, double extensions, invisible text-direction tricks in filenames, macro-enablement requests |
| **HTML Source** | Hidden text, embedded login forms, tracking pixels, obfuscated characters, `javascript:` and `data:` links, mismatched link text |
| **Email Headers** | From/Reply-To mismatch, Return-Path mismatch, display-name spoofing, free-mail senders, Message-ID mismatch, spam headers, SPF/DKIM/DMARC failures |

> HTML and header analysis only activate when you paste raw source (via **View Source** / **Show Original** in your mail client). Plain body text still scores, but with fewer checks available.

---

## 🗂️ Project Structure

```
Phishing Email Analyzer/
├── index.html               →  page structure, privacy notice, disclaimer, form & scoring reference table
├── css/
│   └── styles.css           →  the whole design system (dark "security console" theme)
├── js/
│   ├── rules.js             →  ALL detection rules + their score weights (data, in one place)
│   ├── urls.js              →  URL extraction and domain trickery analysis
│   ├── headers.js           →  parses pasted raw headers (SPF/DKIM/DMARC, From/Reply-To)
│   ├── html.js              →  raw HTML source analysis (hidden text, tracking pixels, forms)
│   ├── analyser.js          →  the scoring engine (turns findings into 0–100 + classification)
│   ├── recommendations.js   →  advice generated from what was found
│   ├── samples.js           →  the 7 fictional demo emails
│   ├── ui.js                →  draws the gauge, findings list, evidence snippets and report
│   └── app.js               →  wires the buttons, clipboard, downloads and keyboard shortcuts
└── tests/
    ├── selftest.html         →  in-browser test page — pass/fail report against all samples
    └── headless-check.js    →  Node.js runner — no browser, no dependencies required
```

Scripts are loaded as plain (non-module) scripts in a fixed order so the site works when opened straight from disk with no web server.

---

## 📧 Built-in Demonstration Emails

Seven fictional messages are available as one-click buttons on the page. No real or working malicious links are used — every domain ends in the reserved `.example` suffix and every IP address is from the documentation ranges `192.0.2.0/24` and `203.0.113.0/24`.

| Example | Expected Result |
| :--- | :---: |
| Obvious phishing | **High Risk** (100, capped) |
| Sophisticated phishing | **High Risk** (62) |
| Fake Microsoft 365 warning with failing SPF/DKIM/DMARC | **High Risk** (100, capped) |
| Fake parcel delivery | **Suspicious** (50) |
| Fake invoice / BEC | **High Risk** (68) |
| Malicious attachment (macro spreadsheet + `.iso`) | **High Risk** (78) |
| Legitimate email with passing authentication | **No Obvious Warning Signs** (0) |

---

## 🧪 Running the Tests

**In a browser** — open `tests/selftest.html` for three tables:
- Engine results vs. expected bands
- Feature coverage (one row per indicator group)
- Robustness checks (empty input, junk input, very large input, raw HTML detection, deterministic scoring)

**In a terminal** (requires Node.js — optional):

```powershell
node tests\headless-check.js
```

Prints the score, band, and fired rules for each demo email, then validates each expectation. Also smoke-tests each indicator group and confirms empty/malformed inputs are handled gracefully.

> Please re-run one of these after changing any rule or weight.

---

## ⚙️ Customising It

| What to Change | Where & How |
| :--- | :--- |
| **Adjust a score weight** | Open `js/rules.js`, find the rule, change its `points` value |
| **Add a body-language rule** | Copy an entry in `BODY_RULES` — give it a new `id`, `title`, `why`, `advice`, `severity`, `points`, and one or more `patterns` (RegExp). It appears automatically in results, score arithmetic, and the reference table |
| **Add a brand to look-alike checks** | Add an entry to `BRANDS` in `js/rules.js` with its display name, hint `tokens`, and genuine `domains` |
| **Change the risk bands** | Edit the `BANDS` array at the top of `js/analyser.js` and the band description caption in `index.html` |

---

## ⚠️ What It Deliberately Does Not Do

- Does **not** check domain age, reputation, or blocklists — that would require contacting the internet
- Does **not** open, follow, or resolve links — a shortened link is reported as hidden, never expanded
- Does **not** inspect attachment contents, only filenames
- Does **not** read images, PDF text, or QR codes
- Does **not** store anything you paste

---

## 🛑 Safety Notes

- **Never click** a suspicious link, open an attachment, or scan a QR code just to test it
- **Verify independently** — use the organisation's official app or website, or a phone number you already have, never one from the message
- A **low score** means "nothing obvious was found", not "this is safe"
- If you already acted on a suspicious message: change the password, enable MFA, and contact your bank or IT team immediately

---

## 👤 Author

**J. Jeffrey Shalom**
- **GitHub**: [@jeffrey-theog06](https://github.com/jeffrey-theog06)
- **Role**: Security Engineer Enthusiast & Full-Stack Developer

---

## 📄 Licence & Intent

Built as a learning project for defensive security education. Use it to train your eye, to understand what phishing messages have in common, and to explain risk to others. It is not a substitute for professional email security controls.
