# MoorAI Browser Guard: store listing text

Text for the Chrome Web Store and Microsoft Edge Add-ons submission forms. The submission itself (developer
account, fee, listing, review) is the owner's step; nothing in this repository submits anything. Package the
upload with `node scripts/browser-ext-package.mjs` (writes `dist/browser-ext/moorai-browser-guard-<version>.zip`).

## Name

MoorAI Browser Guard

## Short description (132 characters or fewer)

On-device prompt guard for browser AI apps. Detection runs locally; only a category, risk level and keyed hash can leave.

## Detailed description

MoorAI Browser Guard reviews the prompt you type into a browser AI app before it is sent, on your own
machine. When the text looks like it contains a secret, an access key, a private key, a payment card or other
personal data, it shows a short in-page notice. In Coach mode you can send anyway or cancel. In Block mode a
high-severity finding (secrets, keys, cards) is not sent.

Supported sites: ChatGPT, Claude, Microsoft Copilot, Google Gemini, Perplexity, Mistral Le Chat, DeepSeek and
Grok.

Detection is deterministic pattern matching that runs inside the page. There is no model and no remote
scanning. If your organization runs a MoorAI console, the extension can send it a content-free signal: the
finding's category, its risk level, a keyed one-way hash and the site's host name. The prompt text is never
sent.

Organizations can install it for every managed browser with the standard force-install policy and set the
console URL, install token and mode through browser policy.

## Category

Productivity (Chrome Web Store) / Productivity (Edge Add-ons)

## Single purpose

Warn the user, before a prompt is sent to a browser AI app, when the prompt contains a secret, credential or
personal data, and optionally report a content-free signal of that warning to the organization's MoorAI console.

## Permission justifications

| Permission | Why it is needed |
|---|---|
| `activeTab` | Lets the extension act on the AI app tab the user is using when they open the extension. |
| `storage` | Saves the user's settings (mode, console URL, install token) and reads the settings an administrator sets through browser policy (managed storage). |
| `https://chatgpt.com/*` | Runs the on-device prompt check in ChatGPT's composer. |
| `https://chat.openai.com/*` | Runs the on-device prompt check on ChatGPT's former domain. |
| `https://claude.ai/*` | Runs the on-device prompt check in Claude's composer. |
| `https://copilot.microsoft.com/*` | Runs the on-device prompt check in Microsoft Copilot's composer. |
| `https://gemini.google.com/*` | Runs the on-device prompt check in Google Gemini's composer. |
| `https://perplexity.ai/*` | Runs the on-device prompt check in Perplexity's composer. |
| `https://www.perplexity.ai/*` | Runs the on-device prompt check on Perplexity's www host. |
| `https://chat.mistral.ai/*` | Runs the on-device prompt check in Mistral Le Chat's composer. |
| `https://chat.deepseek.com/*` | Runs the on-device prompt check in DeepSeek's composer. |
| `https://grok.com/*` | Runs the on-device prompt check in Grok's composer. |
| `https://*/*` (optional, requested at run time) | Requested only for the one origin of the MoorAI console the user enters on the options page, so the background worker can post content-free signals to it. Never requested otherwise. |

Remote code: none. Every script is in the package.

## Data usage (store disclosure form)

- Website content: the text typed into a supported AI app's composer is read inside the page to run the
  check. It is not collected, stored or transmitted.
- Collected and transmitted, only when a console URL is configured: finding category, risk level, a keyed
  one-way hash of the matched span, the site's host name (no path or query), a timestamp, and the install
  token as a request header. Sent only to the console the user or their administrator configured.
- Not sold, not used for advertising, not used for creditworthiness or lending, not transferred to third
  parties.
- Privacy policy: `browser-ext/store/PRIVACY.md`, to be hosted at a public URL by the owner before submission.

## Screenshots (to capture before submission)

1. The Coach notice on a supported site with a test secret in the composer (1280x800).
2. The options page.
3. The options page showing "managed by your organization".
