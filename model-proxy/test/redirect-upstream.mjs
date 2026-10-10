// Test-only preload for the real CLI process (NODE_OPTIONS=--import=<this file's URL>): the proxy's
// https upstream requests to a host named in MOORAI_TEST_UPSTREAM_REDIRECT ({ "<host>": "http://127.0.0.1:<port>" })
// go to that fake instead, path and query unchanged, with the URL the proxy built in x-test-original-url.
// Any other https request, and any fetch to a Google host, throws: no real provider is ever called.
import http from "node:http";
import https from "node:https";

const map = JSON.parse(process.env.MOORAI_TEST_UPSTREAM_REDIRECT || "{}");

https.request = function request(url, opts, cb) {
  if (typeof opts === "function") { cb = opts; opts = {}; }
  const u = url instanceof URL ? url : new URL(String(url));
  const to = map[u.hostname];
  if (!to) throw new Error(`redirect-upstream: https to ${u.hostname} refused in tests`);
  return http.request(new URL(u.pathname + u.search, to), { ...opts, headers: { ...(opts.headers || {}), "x-test-original-url": u.href }, agent: undefined }, cb);
};
https.get = () => { throw new Error("redirect-upstream: https.get refused in tests"); };

const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (/^https?:\/\/[^/]*googleapis\.com/i.test(href)) return Promise.reject(new Error("redirect-upstream: fetch to a Google host refused in tests"));
  return realFetch(input, init);
};
