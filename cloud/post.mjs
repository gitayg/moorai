// POST the inventory to the console: /api/cloud-inventory, authenticated by the tenant install token
// (the same X-Install-Token header the hook uses). Body is exactly postBody() from inventory.mjs.
export async function postInventory(body, { serverUrl, installToken, timeoutMs = 30000 }) {
  const url = new URL("/api/cloud-inventory", serverUrl);
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "x-install-token": installToken },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs)
  });
  let reply = null;
  try { reply = await res.json(); } catch { /* non-JSON reply */ }
  return { status: res.status, reply };
}
