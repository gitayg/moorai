// A stub OpenAI-compatible model for test/quarantine-reader-hook.test.mjs, on 127.0.0.1.
//   node quarantine-stub-model.mjs <infoFile> daemon   re-spawns itself detached and exits, so the server is
//                                                       re-parented (ppid 1) and sits outside the test's process
//                                                       tree, like a model runtime the user started
//   node quarantine-stub-model.mjs <infoFile> serve    serves in this process (a child of whoever started it)
// It writes { port, pid } to <infoFile> once listening. /v1/models, /v1/chat/completions (the reply set by POST
// /__reply), GET /__state ({ chats, lastChat }), POST /__quit.
import http from "node:http";
import { writeFileSync, renameSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const [infoFile, mode] = process.argv.slice(2);
if (mode === "daemon") {
  const c = spawn(process.execPath, [fileURLToPath(import.meta.url), infoFile, "serve"], { detached: true, stdio: "ignore" });
  c.unref();
  process.exit(0);
}
const st = { chats: 0, lastChat: "", reply: "{}" };
const server = http.createServer((req, res) => {
  let b = "";
  req.on("data", (c) => { b += c; });
  req.on("end", () => {
    const json = (o) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };
    if (req.url === "/v1/models") return json({ data: [{ id: "stub" }] });
    if (req.url === "/v1/chat/completions" && req.method === "POST") { st.chats++; st.lastChat = b; return json({ choices: [{ message: { role: "assistant", content: st.reply } }] }); }
    if (req.url === "/__reply" && req.method === "POST") { st.reply = b; return json({ ok: true }); }
    if (req.url === "/__state") return json({ chats: st.chats, lastChat: st.lastChat });
    if (req.url === "/__quit") { json({ ok: true }); setTimeout(() => process.exit(0), 10); return; }
    res.writeHead(404); res.end();
  });
});
setTimeout(() => process.exit(0), 120000).unref();
server.listen(0, "127.0.0.1", () => {
  writeFileSync(`${infoFile}.tmp`, JSON.stringify({ port: server.address().port, pid: process.pid }));
  renameSync(`${infoFile}.tmp`, infoFile);
});
