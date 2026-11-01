// Free throwaway web hosts for pkg-throwaway-host (cli/mcp-package/heuristics.mjs). The criterion for a
// domain here: anyone can publish content, a tunnel or a request-capture endpoint under it in minutes,
// for free and with no identity check, and the URL is disposable. That makes it a cheap, deniable place
// for a second-stage payload or a drop box (a PyPI MCP server described in a public research write-up, October 2026, fetched its
// payload image from a tiiny.site subdomain). A published package rarely needs to hard-code one, so a
// live fetch from one is a WARNING (notify), never a verdict: a demo or a test helper can do it too.
//
// Deliberately NOT here: hosts with heavy legitimate package use (raw.githubusercontent.com, GitHub
// gists, Discord or Slack webhooks, Telegram's bot API), and general cloud or CDN domains.
// Matched as a suffix on the parsed hostname at a label boundary: "x.tiiny.site" and "tiiny.site"
// match "tiiny.site"; "eviltiiny.site" and "tiiny.site.example.com" do not.

export const THROWAWAY_HOSTS = [
  // static / page hosting
  "tiiny.site", "glitch.me",
  // paste sites
  "pastebin.com", "paste.ee", "hastebin.com", "dpaste.com", "rentry.co", "termbin.com", "ix.io", "sprunge.us",
  // anonymous file drops
  "transfer.sh", "file.io", "0x0.st", "temp.sh", "catbox.moe",
  // anonymous tunnels
  "ngrok-free.app", "ngrok-free.dev", "ngrok.io", "trycloudflare.com", "loca.lt", "serveo.net", "lhr.life",
  // request capture / out-of-band callback services
  "webhook.site", "requestbin.net", "m.pipedream.net", "interact.sh", "oast.fun", "oast.pro", "oast.live",
  "oast.site", "oast.online", "oast.me", "burpcollaborator.net"
];

export function throwawayHost(hostname, list = THROWAWAY_HOSTS) {
  const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!h) return null;
  for (const d of list) if (h === d || h.endsWith(`.${d}`)) return d;
  return null;
}
