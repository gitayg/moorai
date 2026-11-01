# MoorAI Browser Guard privacy policy

MoorAI Browser Guard is a browser extension that checks the prompt you type into a supported browser AI app
before it is sent.

## What the extension reads

On the supported sites only (ChatGPT, Claude, Microsoft Copilot, Google Gemini, Perplexity, Mistral Le Chat,
DeepSeek, Grok), it reads the text in the prompt box when you send it and runs pattern checks for secrets,
keys, payment cards and personal data inside the page. The prompt text never leaves your browser and is not
stored.

## What can leave your browser

Nothing, unless you or your organization's administrator configure a MoorAI console URL. When one is
configured, each finding produces one signal sent to that console only, containing:

- the finding's category (for example "Secret: API key") and risk level;
- a keyed one-way hash of the matched text, computed with your organization's install token, so the text
  cannot be recovered from it;
- the host name of the AI site (for example `chatgpt.com`), never the page path or query string;
- a timestamp;
- the install token, as a request header, so the console knows which organization the signal belongs to.

The extension sends nothing to MoorAI or any other party. It has no analytics and loads no remote code.

## What is stored

Your settings (mode, console URL, install token, whether to send signals) are stored in the browser's
extension storage. Settings an administrator sets through browser policy are read from the browser's managed
storage.

## Your choices

Leave the console URL empty, or turn off "Send content-free signals", to use the extension fully locally.
Removing the extension removes its settings. If your organization installed it by policy, contact your
administrator.

## Contact

Through https://moorai.dev.
