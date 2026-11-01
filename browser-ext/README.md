# MoorAI Browser Guard

A companion **Manifest V3** browser extension (Chrome / Edge) that extends MoorAI's guardrails beyond
coding-agent CLIs to **browser GenAI** — ChatGPT, Claude, Microsoft Copilot, Google Gemini, Perplexity,
Mistral Le Chat, DeepSeek, and Grok on the web.

It reviews the prompt you type into a browser AI **before it is sent**, entirely on your machine, and —
mirroring the MoorAI agent — it is **content-free by construction**.

## What it does

- Watches the site's prompt composer (textarea / contenteditable) on:
  - ChatGPT — `https://chatgpt.com/*`, `https://chat.openai.com/*`
  - Claude — `https://claude.ai/*`
  - Copilot — `https://copilot.microsoft.com/*`
  - Gemini — `https://gemini.google.com/*`
  - Perplexity — `https://perplexity.ai/*`, `https://www.perplexity.ai/*`
  - Mistral Le Chat — `https://chat.mistral.ai/*`
  - DeepSeek — `https://chat.deepseek.com/*`
  - Grok — `https://grok.com/*`
- Intercepts the send action (**Enter** without Shift, and the **send button** click).
- Scans the text **locally** with a deterministic regex/rules engine (`detectors.js`) — a faithful
  subset of the agent's own detectors (secrets, keys, PII, payment data, prompt injection).
- On a finding, shows an inline, non-blocking **coach** banner:
  _"MoorAI: this looks like it contains &lt;category&gt; — are you sure?"_ with **Send anyway** / **Cancel**.
- In **block** mode, a **high-severity** finding (secret, key, card, private key) **prevents the send**.
- Optionally emits a **content-free signal** to a MoorAI console.

## Content-free guarantee

The prompt text **never leaves your browser**. Detection runs in the content script. The only thing that
can be sent — and only if you configure a console URL — is a signal shaped exactly like the MoorAI agent's:

```
POST <serverUrl>/api/alerts
X-Install-Token: <token>
{ threatId, category, riskLevel, stage: "browser", tool: "browser:<site>", ts, contentHash, host }
```

`contentHash` is a **keyed one-way hash** — HMAC-SHA-256 under your tenant's install token, the same
hash the agent uses (`cli/content-hash.mjs`), so a span hashes identically in the browser and in the
CLI. With no install token configured it is the explicit `h2:nokey` marker, never a weaker hash. Of the
matched span — the matched text is used only to compute that hash and is then discarded. A payment-card
number (#90) is the exception: its hash is keyed with a random value made when the page loads (`proc:` and
16 hex), because a card number comes from a space small enough that anyone holding the install token could
enumerate the tenant-keyed hash back to it; two pages, or a reload, hash the same card differently. No prompt text,
no matched substring, and only the URL **host** (never the full URL or query string) is included.
Reporting **fails open and silent**: any network error, or no configured server, simply sends nothing.

The POST is made by the extension's **background service worker** (`background.js`), not the content
script: a content script's fetch runs under the page's origin and same-origin policy even when the extension
holds host permission. The content script hands the alerts over with `chrome.runtime.sendMessage`; the
worker accepts messages from this extension only, rebuilds each alert from the allow-listed fields above
(type- and length-checked, anything else dropped), and posts only to an https console origin (or http on
loopback) it holds host permission for.

## Store build and managed force-install

- `node scripts/browser-ext-package.mjs` writes the store upload zip (`dist/browser-ext/moorai-browser-guard-<version>.zip`):
  exactly the files the manifest and options page reference, deterministic bytes.
- `--console-origin https://console.example.com` writes a self-hosted variant whose manifest carries that
  origin as a host permission, so a force-installed copy reports with no user step.
- `store/listing.md` holds the listing text, single-purpose statement, a justification per permission and the
  data-usage disclosure; `store/PRIVACY.md` is the privacy policy. Submitting to the Chrome Web Store and Edge
  Add-ons (developer accounts, review, hosting the privacy policy at a public URL) is the owner's step.
- `policy/` holds force-install templates for Chrome and Edge (macOS `.mobileconfig`, Windows `.reg`, Linux
  JSON, an ADMX/ADML pair for the managed settings, Intune steps). Render them with the store-assigned id:
  `node scripts/browser-ext-policy.mjs --id <id> --out <dir> --server-url ... --install-token ... --mode coach`.
- Administrators set `serverUrl`, `installToken`, `mode`, `reportEnabled` and `lockSettings` through browser
  policy (`managed-schema.json`, read from `chrome.storage.managed`). A managed value wins over the user's own;
  with `lockSettings` the options page shows them read-only.
- Icons are drawn by `node scripts/browser-ext-icons.mjs` (no image tooling).

There is **no bundled ML model** — detection is deterministic regex/rules only.

## Detection vocabulary

`detectors.js` is a small, self-contained, faithful subset of the agent's detectors, ported verbatim from:

- `data/detectors.js` — `dlp-email`, `dlp-national-id`, `dlp-payment-card` (with the issuer ranges of
  `data/card-iin.js`), `dlp-iban`,
  `dlp-private-key`, `dlp-jwt`, `dlp-phone`, `inj-ignore`
- `data/secrets-patterns.js` — prefix-anchored provider tokens (AWS, GitHub, Slack, Stripe, Google,
  OpenAI/Anthropic, DB connection strings) plus the **entropy + allowlist gate** for the two "shapeless"
  cases (generic secret assignment, AWS secret key)

`content-hash.js` is a synchronous plain-JS HMAC-SHA-256 (the gate must run inside a capture-phase event handler, so `crypto.subtle` is unusable); `test/content-hash.test.mjs` asserts it matches `node:crypto` byte-for-byte, so hashes stay consistent with the agent.

## Load unpacked (Chrome / Edge)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this `browser-ext/` directory.
4. Open the extension's **Options** to choose **Coach** or **Block** mode and (optionally) set your MoorAI
   console URL + install token. When you set a server URL, the browser will prompt to grant that origin
   the reporting host permission (kept out of the always-on permissions for least privilege).
5. Visit any supported site (ChatGPT / Claude / Copilot / Gemini / Perplexity / Le Chat / DeepSeek / Grok)
   and type a prompt containing, e.g., a fake secret — the coach banner appears before the prompt is sent.

## Configuration

| Setting        | Values          | Meaning                                                            |
| -------------- | --------------- | ------------------------------------------------------------------ |
| Mode           | `coach` (default) / `block` | Coach warns but always lets you proceed; Block prevents a high-severity send. |
| Server URL     | URL or blank    | MoorAI console for content-free signals. Blank = fully local, no reporting.   |
| Install token  | string          | Sent as `X-Install-Token` (same as the agent).                     |
| Send signals   | on/off          | Master switch for reporting.                                       |
| Lock settings  | managed only    | Set by policy: shows the managed values read-only.                 |

Every setting can also come from browser policy (managed storage); a managed value wins.

## Files

```
browser-ext/
  manifest.json        MV3 manifest (minimal permissions; one host perm per supported AI site)
  config.js            effective config: managed policy over the user's options-page values
  background.js        service worker: validates alerts from the content script, POSTs them to the console
  managed-schema.json  managed-storage schema (serverUrl, installToken, mode, reportEnabled, lockSettings)
  icons/               16/32/48/128 px icons (scripts/browser-ext-icons.mjs)
  store/               store listing text + privacy policy
  policy/              Chrome/Edge force-install templates (scripts/browser-ext-policy.mjs renders them)
  content-hash.js      keyed one-way content hash (HMAC-SHA-256), loaded before detectors.js
  detectors.js         on-device, content-free detection engine (agent-subset regexes)
  content.js           composer detection, send interception, coach/block banner
  report.js            builds the content-free alerts and hands them to background.js
  content.css          banner styling
  options.html/.js     configure mode, server URL, token
  test-detectors.mjs   Node unit test for the ported detectors + hash parity
  README.md            this file
```

## Test

```
node browser-ext/test-detectors.mjs
node --test --import ./test/hermetic-env.mjs test/browser-ext-store.test.mjs
```

## Known limitations

- **Site DOM selectors drift.** ChatGPT/Claude/Copilot change their composer and send-button markup
  frequently; the selectors here use ordered fallbacks but may need updating. Detection fails **open**
  (if the composer can't be found, nothing is intercepted — the site works normally).
- Detection is **regex/rules only** — it catches structured secrets/PII shapes, not free-form sensitive
  intent. It complements, not replaces, the MoorAI agent.
