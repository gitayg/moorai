# MoorAI Browser Guard

A companion **Manifest V3** browser extension (Chrome / Edge) that extends MoorAI's guardrails beyond
coding-agent CLIs to **browser GenAI** — ChatGPT, Claude, and Microsoft Copilot on the web.

It reviews the prompt you type into a browser AI **before it is sent**, entirely on your machine, and —
mirroring the MoorAI agent — it is **content-free by construction**.

## What it does

- Watches the site's prompt composer (textarea / contenteditable) on:
  - ChatGPT — `https://chatgpt.com/*`, `https://chat.openai.com/*`
  - Claude — `https://claude.ai/*`
  - Copilot — `https://copilot.microsoft.com/*`
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

`contentHash` is a **one-way djb2 hash** (the same hash the agent uses in `cli/moorai-hook.mjs`) of the
matched span — the matched text is used only to compute that hash and is then discarded. No prompt text,
no matched substring, and only the URL **host** (never the full URL or query string) is included.
Reporting **fails open and silent**: any network error, or no configured server, simply sends nothing.

There is **no bundled ML model** — detection is deterministic regex/rules only.

## Detection vocabulary

`detectors.js` is a small, self-contained, faithful subset of the agent's detectors, ported verbatim from:

- `data/detectors.js` — `dlp-email`, `dlp-national-id`, `dlp-payment-card`, `dlp-iban`,
  `dlp-private-key`, `dlp-jwt`, `dlp-phone`, `inj-ignore`
- `data/secrets-patterns.js` — prefix-anchored provider tokens (AWS, GitHub, Slack, Stripe, Google,
  OpenAI/Anthropic, DB connection strings) plus the **entropy + allowlist gate** for the two "shapeless"
  cases (generic secret assignment, AWS secret key)

The `djb2` hash is copied byte-for-byte from `cli/moorai-hook.mjs` so hashes are consistent with the agent.

## Load unpacked (Chrome / Edge)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this `browser-ext/` directory.
4. Open the extension's **Options** to choose **Coach** or **Block** mode and (optionally) set your MoorAI
   console URL + install token. When you set a server URL, the browser will prompt to grant that origin
   the reporting host permission (kept out of the always-on permissions for least privilege).
5. Visit ChatGPT / Claude / Copilot and type a prompt containing, e.g., a fake secret — the coach banner
   appears before the prompt is sent.

## Configuration

| Setting        | Values          | Meaning                                                            |
| -------------- | --------------- | ------------------------------------------------------------------ |
| Mode           | `coach` (default) / `block` | Coach warns but always lets you proceed; Block prevents a high-severity send. |
| Server URL     | URL or blank    | MoorAI console for content-free signals. Blank = fully local, no reporting.   |
| Install token  | string          | Sent as `X-Install-Token` (same as the agent).                     |
| Send signals   | on/off          | Master switch for reporting.                                       |

## Files

```
browser-ext/
  manifest.json        MV3 manifest (minimal permissions; host perms only for the 3 AI sites)
  detectors.js         on-device, content-free detection engine (agent-subset regexes + djb2)
  content.js           composer detection, send interception, coach/block banner
  report.js            content-free POST to <serverUrl>/api/alerts
  content.css          banner styling
  options.html/.js     configure mode, server URL, token
  test-detectors.mjs   Node unit test for the ported detectors + hash parity
  README.md            this file
```

## Test

```
node browser-ext/test-detectors.mjs
```

## Known limitations

- **Site DOM selectors drift.** ChatGPT/Claude/Copilot change their composer and send-button markup
  frequently; the selectors here use ordered fallbacks but may need updating. Detection fails **open**
  (if the composer can't be found, nothing is intercepted — the site works normally).
- Detection is **regex/rules only** — it catches structured secrets/PII shapes, not free-form sensitive
  intent. It complements, not replaces, the MoorAI agent.
