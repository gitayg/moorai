// What the #85 Stop check hands to threatcl, and how it runs it (cli/boundary-model.mjs validateThreatModels).
// The hook runs `threatcl validate` outside the agent's sandbox and egress controls on a model the agent wrote.
// threatcl's documentation could not be checked offline, so its `imports` and `including` are assumed able to
// fetch remote content or read other files. Defence in depth:
//
// 1. Content gate. A model is refused ("untrusted-input", threatcl never spawned) when it contains, anywhere and in
//    any case, the word `imports` or `including` (an attribute, a block, or prose: when unsure, refuse); `://`;
//    a \u / \U escape or a ${ / %{ template, either of which could spell a URL or a key the plain-text checks
//    would miss; an HCL file function (file, templatefile, fileexists, fileset, filebase64 and the file hashes,
//    abspath, pathexpand) before "("; a NUL or a U+FFFD (not plain UTF-8). Linear-time patterns only.
// 2. A minimal environment: PATH=/usr/bin:/bin (Windows: SystemRoot and its System32), HOME (Windows: USERPROFILE)
//    set to the fresh empty working directory, every proxy variable pointed at a closed port on 127.0.0.1,
//    NO_PROXY empty, nothing else: not the user's home, tokens or the hook's proxies. HOME is set rather than
//    left out because a child with no HOME resolves the real one from the password database.
// 3. macOS: wrapped in /usr/bin/sandbox-exec with network denied, when that binary passes the root-ownership walk.
//    Linux has no such wrapper here: the gate and the environment are what holds. Windows never runs threatcl
//    (cli/boundary-model.mjs whichThreatcl: "unsupported"), so its environment form below is not used.

export const GATE_MAX = 1_048_576;
const FETCH_WORD = /(?:^|[^A-Za-z0-9_-])(?:imports|including)(?![A-Za-z0-9_-])/i;
const URL_MARK = /:\/\//;
const ESCAPE = /\\[uU]/;
const TEMPLATE = /[$%]\{/;
const FILE_FN = /(?:^|[^A-Za-z0-9_-])(?:file|templatefile|fileexists|fileset|filebase64|filemd5|filesha1|filesha256|filesha512|filebase64sha256|filebase64sha512|abspath|pathexpand)[ \t\r\n]*\(/i;
const NOT_PLAIN = /[\u0000\uFFFD]/;

// true when the model text may be handed to threatcl.
export function threatclInputSafe(text) {
  if (typeof text !== "string" || text.length > GATE_MAX) return false;
  if (FETCH_WORD.test(text)) return false;
  if (URL_MARK.test(text)) return false;
  return !ESCAPE.test(text) && !TEMPLATE.test(text) && !FILE_FN.test(text) && !NOT_PLAIN.test(text);
}

const CLOSED = "http://127.0.0.1:9";
// The whole environment threatcl gets; home is the run's fresh empty working directory.
export function threatclEnv(home, platform = process.platform, systemRoot = process.env.SystemRoot) {
  const proxies = { HTTP_PROXY: CLOSED, HTTPS_PROXY: CLOSED, ALL_PROXY: CLOSED, NO_PROXY: "", http_proxy: CLOSED, https_proxy: CLOSED, all_proxy: CLOSED, no_proxy: "" };
  if (platform === "win32") { const root = systemRoot || "C:\\Windows"; return { SystemRoot: root, PATH: `${root}\\System32`, USERPROFILE: home, ...proxies }; }
  return { PATH: "/usr/bin:/bin", HOME: home, ...proxies };
}

export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const NO_NETWORK = "(version 1)(allow default)(deny network*)";
// The command line: under sandbox-exec with network denied when sandboxOk (macOS, a root-owned sandbox-exec).
export function threatclCommand(bin, args, { sandboxOk = false } = {}) {
  return sandboxOk ? { file: SANDBOX_EXEC, args: ["-p", NO_NETWORK, bin, ...args] } : { file: bin, args };
}
