// Weakening oversight (#84) for MCP filesystem write tools. A filesystem-style MCP server's write / edit /
// move / create tool (the reference server's write_file, edit_file, move_file, create_directory; Desktop
// Commander's write_file and edit_block; Serena's create_text_file; JetBrains' replace_file_text_by_path …)
// changes a local file exactly as Write / Edit does, so its path arguments get the same check
// (cli/oversight-signals.mjs oversightEditSignals): the memory-file and protected-path checks, and the
// before / after judgement of runtime code and tests.
//
// A write tool is named by a write verb (write, edit, move, rename, create, append, replace, insert, patch,
// save, overwrite, update) with a file noun (file, text_file, directory, dir, folder, block, text, content,
// path, document), or a bare verb (`write`, `edit`). A named remote-repository tool (github / gitlab / gitea /
// bitbucket create_or_update_file, push_files …: REMOTE_REPO_TOOL) writes no local file and is not judged. In
// any other call an argument naming a remote repository or bucket (owner, repo, bucket …;
// cli/mcp-file-args.mjs namesRemoteLocation) only makes RELATIVE paths ambiguous, as there: absolute, ~ and
// file:// paths are always judged, so adding a `repo` argument switches nothing off. A path with a known
// remote scheme (http, https, s3, gs, git, ssh) is not local; any other `scheme:` string is judged both as
// written and without its scheme, and is analysis-incomplete (how the server reads it is unknown).
//
// The arguments map onto the Write / Edit call the check already reads:
//   content / text / contents / file_text / new_content       → Write (mode "append", or an append tool: the
//                                                               file's text plus the content);
//   edits: [{ oldText, newText } | { old_string, new_string }] → MultiEdit;
//   old_string + new_string (old_str / new_str, oldText / newText, search / replace) → Edit;
//   move / rename: the destination is a Write of the source's text (read as below, else a path-only check), the
//   source a path-only check; anything else (create_directory …) is a path-only check (memory files and
//   protected paths).
// The target's current text (a regular file of at most 1 MiB) is the "before"; an existing file over that is
// held as analysis-incomplete for a Write, as in the hook's Write branch, and so is a move whose source exists
// but is over that size or cannot be read, onto runtime code or a test. Nothing is written, and only the signal
// enums leave.
import { statSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { oversightEditSignals, beforeAfter, OVERSIGHT_SIGNALS } from "./oversight-signals.mjs";
import { namesRemoteLocation } from "./mcp-file-args.mjs";

const READ_MAX = 1_048_576;
const MAX_PATHS = 16;
const VERB = /(?:^|_)(?:write|edit|move|rename|create|append|replace|insert|patch|save|overwrite|update)(?:_|$)/;
const NOUN = /(?:^|_)(?:files?|text_?file|director(?:y|ies)|dirs?|folders?|block|text|content|path|document)(?:_|$)/;
const BARE = /^(?:write|edit|append|move|rename)$/;
const MOVE = /(?:^|_)(?:move|rename)(?:_|$)/;
const APPEND = /(?:^|_)append(?:_|$)/;
const REMOTE_REPO_TOOL = /^mcp__[\w.-]*(?:github|gitlab|gitea|bitbucket)[\w.-]*__(?:create_or_update_file|create_file|update_file|push_files|delete_file)$/i;
const REMOTE_SCHEME = /^(?:https?|s3|gs|git|ssh):/i;

const localName = (tool) => String(tool || "").split("__").slice(2).join("__").replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
export function mcpWriteTool(tool) {
  if (typeof tool !== "string" || !tool.startsWith("mcp__")) return false;
  const n = localName(tool);
  return Boolean(n) && (BARE.test(n) || (VERB.test(n) && NOUN.test(n)));
}

const PATH_KEYS = ["path", "file_path", "filePath", "file", "filename", "fileName", "relative_path", "relativePath", "pathInProject", "target_path", "targetPath", "uri"];
const SRC_KEYS = ["source", "src", "from", "old_path", "oldPath", "source_path", "sourcePath"];
const DEST_KEYS = ["destination", "dest", "to", "new_path", "newPath", "target", "destination_path", "destinationPath"];
const TEXT_KEYS = ["content", "contents", "text", "file_text", "fileText", "new_content", "newContent", "data"];
const first = (a, keys) => { for (const k of keys) if (typeof a[k] === "string" && a[k]) return a[k]; return null; };
const str = (v) => typeof v === "string";
const pair = (e) => {
  if (!e || typeof e !== "object") return null;
  for (const [o, n] of [["old_string", "new_string"], ["oldText", "newText"], ["old_str", "new_str"], ["oldString", "newString"], ["search", "replace"]]) if (str(e[o]) && str(e[n])) return { old_string: e[o], new_string: e[n] };
  return null;
};

// → [{ tool: "Write" | "Edit" | "MultiEdit" | "Path", path, input, append?, from? }] for one MCP call (pure).
export function mcpWriteCalls(tool, args) {
  if (!mcpWriteTool(tool) || REMOTE_REPO_TOOL.test(tool) || !args || typeof args !== "object" || Array.isArray(args)) return [];
  const n = localName(tool);
  if (MOVE.test(n)) {
    const src = first(args, SRC_KEYS), dest = first(args, DEST_KEYS);
    const out = [];
    if (dest) out.push(src ? { tool: "Write", path: dest, input: {}, from: src } : { tool: "Path", path: dest, input: {} });
    if (src) out.push({ tool: "Path", path: src, input: {} });
    return out;
  }
  const paths = [first(args, PATH_KEYS), ...(Array.isArray(args.paths) ? args.paths.filter((p) => str(p) && p) : [])].filter(Boolean).slice(0, MAX_PATHS);
  if (!paths.length) return [];
  const edits = Array.isArray(args.edits) ? args.edits.map(pair).filter(Boolean) : [];
  const one = pair(args);
  const text = TEXT_KEYS.find((k) => str(args[k]));
  return paths.map((path) => {
    if (edits.length) return { tool: "MultiEdit", path, input: { edits } };
    if (one) return { tool: "Edit", path, input: one };
    if (text) {
      const call = { tool: "Write", path, input: { content: args[text] } };
      if (APPEND.test(n) || /^append$/i.test(String(args.mode || ""))) call.append = true;
      return call;
    }
    return { tool: "Path", path, input: {} };
  });
}

// A path argument → { paths: [absolute …], unsure, relative }: [] for a known remote scheme; unsure for a
// file: URL that does not parse or a scheme we do not know (judged as written and without the scheme);
// relative: it was resolved against cwd (ignored when the call names a remote location).
const absOne = (s, base) => (s === "~" || s.startsWith("~/") ? join(homedir(), s.slice(2)) : isAbsolute(s) ? resolve(s) : resolve(base, s));
const relativeArg = (s) => !(s === "~" || s.startsWith("~/") || isAbsolute(s));
function absOf(p, base) {
  if (/^file:/i.test(p)) { try { return { paths: [resolve(fileURLToPath(p))], unsure: false, relative: false }; } catch { return { paths: [absOne(p, base)], unsure: true, relative: true }; } }
  if (REMOTE_SCHEME.test(p)) return { paths: [], unsure: false, relative: false };
  if (/^[A-Za-z][A-Za-z0-9+.-]+:/.test(p) && !/^[A-Za-z]:[\\/]/.test(p)) {
    const rest = p.slice(p.indexOf(":") + 1).replace(/^\/\/(?=\/)/, "");
    return { paths: [...new Set([absOne(p, base), ...(rest ? [absOne(rest, base)] : [])])], unsure: true, relative: relativeArg(rest || p) };
  }
  return { paths: [absOne(p, base)], unsure: false, relative: relativeArg(p) };
}
// The file's text when it is a regular file of at most READ_MAX: { file, unread } (unread: a regular file over).
function readOf(abs) {
  let st;
  try { st = statSync(abs); } catch { return { file: null, unread: false }; }
  if (!st.isFile()) return { file: null, unread: false };
  if (st.size > READ_MAX) return { file: null, unread: true };
  try { return { file: readFileSync(abs, "utf8"), unread: false }; } catch { return { file: null, unread: true }; }
}

// → the #84 signals the MCP call raises, in OVERSIGHT_SIGNALS order. opts: { cwd, surfaces }.
export function oversightMcpSignals(tool, args, { cwd = "", surfaces = null } = {}) {
  const out = new Set();
  try {
    const base = typeof cwd === "string" && cwd ? cwd : process.cwd();
    const remote = namesRemoteLocation(args);
    for (const call of mcpWriteCalls(tool, args)) {
      const where = absOf(call.path, base);
      if (remote && where.relative) continue;
      if (where.unsure) out.add("analysis-incomplete");
      // A move's source: its text, or "unread" when it exists but is too large or cannot be read.
      let src = null;
      if (call.from) {
        const w = absOf(call.from, base);
        if (w.unsure) out.add("analysis-incomplete");
        const r = w.paths.length === 1 && !(remote && w.relative) ? readOf(w.paths[0]) : { file: null, unread: false };
        src = { file: r.file, unread: r.unread };
      }
      for (const abs of where.paths) {
        let sigs;
        if (call.tool === "Path") sigs = oversightEditSignals({ path: abs, before: null, after: "", surfaces, cwd: base });
        else if (src && src.file === null) sigs = oversightEditSignals({ path: abs, before: null, after: "", surfaces, cwd: base, beforeUnread: src.unread });
        else {
          const { file, unread } = readOf(abs);
          let input = src ? { content: src.file } : call.input;
          if (call.append) input = { content: (file || "") + input.content };
          const { before, after } = beforeAfter({ tool: call.tool, input, file });
          sigs = oversightEditSignals({ path: abs, before, after, surfaces, cwd: base, beforeUnread: call.tool === "Write" && unread });
        }
        for (const x of sigs) out.add(x);
      }
    }
  } catch { out.add("analysis-incomplete"); }
  return OVERSIGHT_SIGNALS.filter((s) => out.has(s));
}
