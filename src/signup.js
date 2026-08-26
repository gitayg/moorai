// In-app management-account signup, and the wait for the user to click the verification email.
//
// Pure protocol, every dependency injected: src/api.js reads localStorage at module scope and so
// cannot be imported under node, which is exactly why this half lives on its own — it is unit-tested
// without a webview. Nothing here touches window, localStorage or the console.
//
// SECURITY: the claim token is the ONLY thing that ever reaches the claim endpoint. The email
// address and the tenant are deliberately not part of that request and must never become part of it
// — a "has this email verified yet?" lookup is an account-enumeration oracle for anyone who can
// reach the server. The claim token is also single-use and lives only for the polling session; it is
// never persisted and never logged.

// Creates the tenant and mails the verification link. `claim: true` is what makes the server hand
// back a claim token; without it the endpoint behaves exactly as it did before this feature.
export async function startSignup({ base, name, email, fetchImpl }) {
  const r = await fetchImpl(`${base}/api/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, claim: true })
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `signup failed (${r.status})`);
  return { tenant: d.tenant, emailed: d.emailed, claimToken: d.claimToken };
}

// Polls until the account is verified. 202 = not clicked yet, 200 = ready (and the token is burned
// server-side on that first read), 404 = unknown / already used / past the 30-minute window.
export async function pollClaim({ base, claimToken, fetchImpl, sleep, intervalMs = 3000, timeoutMs = 10 * 60 * 1000, onPending, now = Date.now }) {
  const deadline = now() + timeoutMs;
  for (;;) {
    const r = await fetchImpl(`${base}/api/signup/claim?claim=${encodeURIComponent(claimToken)}`);
    if (r.status === 200) {
      const d = await r.json();
      return { tenant: d.tenant, installToken: d.installToken, serverUrl: d.serverUrl };
    }
    if (r.status === 404) throw new Error("this signup link expired or was already used — create the account again");
    if (onPending) onPending();
    if (now() + intervalMs >= deadline) throw new Error("timed out waiting for email verification — click the link we emailed you, then try again");
    await sleep(intervalMs);
  }
}
