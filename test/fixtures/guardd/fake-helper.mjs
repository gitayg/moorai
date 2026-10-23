// An in-process stand-in for moorai-guardd's IPC endpoint (contract §3) in an injected tree laid out like
// guardd's Paths::under(<root>): <root>/run/hook.sock and <root>/run/device.pub, every directory owned by
// the test user and not writable by group or others, so the hook client's ownership walk passes with
// trustUid = the test user. It answers `hello` with a real device-key proof and `policy` per `behavior`.
import net from "node:net";
import { mkdirSync, writeFileSync, chmodSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import { encodeFrame, FrameDecoder, helloProofInput } from "../../../cli/guardd-client.mjs";

// A short base directory: a Unix socket path must stay under 104 bytes on macOS.
export function shortTempRoot(prefix) {
  const base = realpathSync(tmpdir().length > 60 ? "/tmp" : tmpdir());
  const root = mkdtempSync(join(base, prefix));
  chmodSync(root, 0o755);
  return root;
}

export function deviceKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const keyId = createHash("sha256").update(Buffer.from(spki, "base64").subarray(12)).digest("hex").slice(0, 32);
  return { privateKey, spki, keyId };
}

// behavior: { tenant, policy: () => reply fields | "hang" | "close", proofKey? (sign hello with another key) }
export async function startFakeHelper(root, behavior) {
  const run = join(root, "run");
  mkdirSync(run, { recursive: true });
  chmodSync(run, 0o755);
  const key = deviceKeyPair();
  writeFileSync(join(run, "device.pub"), `${key.spki}\n`);
  chmodSync(join(run, "device.pub"), 0o644);
  const requests = [];
  const socks = new Set();
  const server = net.createServer((sock) => {
    socks.add(sock);
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => {});
    const dec = new FrameDecoder();
    sock.on("data", (chunk) => {
      dec.push(chunk);
      for (let m = dec.next(); m; m = dec.next()) {
        requests.push(m);
        if (m.op === "hello") {
          const signer = behavior.proofKey || key;
          const proof = edSign(null, Buffer.from(helloProofInput(m.nonce, key.keyId, "0.1.0")), signer.privateKey).toString("base64");
          sock.write(encodeFrame({ v: 1, id: m.id, op: "hello", proto: 1, helperVersion: "0.1.0", tenant: behavior.tenant, deviceId: "d".repeat(32), keyId: key.keyId, caps: ["policy"], proof }));
        } else if (m.op === "policy") {
          const r = behavior.policy(m);
          if (r === "hang") continue;
          if (r === "close") { sock.destroy(); return; }
          sock.write(encodeFrame({ v: 1, id: m.id, op: "policy", ...r }));
        }
      }
    });
  });
  const endpoint = join(run, "hook.sock");
  await new Promise((r) => server.listen(endpoint, r));
  return {
    key,
    requests,
    connectOpts: { root, trustUid: process.getuid(), endpoint: "/run/hook.sock", devicePubPath: "/run/device.pub" },
    close: () => new Promise((r) => { for (const s of socks) s.destroy(); server.close(() => r()); })
  };
}
