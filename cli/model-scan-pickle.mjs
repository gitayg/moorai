// Static pickle scanner: walks the opcode stream of protocols 0-5 WITHOUT executing it and reports the
// globals the stream would import and call. A pickle's only way to run code is to import a callable
// (GLOBAL / STACK_GLOBAL / INST / EXT*) and call it (REDUCE / NEWOBJ / NEWOBJ_EX / INST / OBJ, or BUILD
// through __setstate__), so the imports are the whole story.
//
// Opcode table: CPython Lib/pickletools.py (the `opcodes` list) and Lib/pickle.py. A small symbolic
// stack tracks strings, globals and the memo, so STACK_GLOBAL resolves its module and name even when
// they were memoised (BINPUT / MEMOIZE) and fetched back (BINGET), which is how scanners that only
// read the previous two string opcodes get evaded.
//
// Classes (severity):
//   dangerous-import  critical  a global from the deny list (os, subprocess, builtins.eval, …)
//   indirect-call     high      a call whose callable is not a global (the result of another call):
//                               getattr(__import__("os"), "system")(…) shapes
//   unresolved-global medium    STACK_GLOBAL whose module or name is not a constant string, or an EXT
//                               opcode (a copyreg extension code the scanner cannot resolve)
//   nested-load       medium    a global that deserializes another payload (torch.load,
//                               torch.storage._load_from_bytes, numpy.load)
//   unknown-import    low       a global on neither list (a custom class in a full-model pickle)
//   malformed         medium    an unknown opcode, a stack or mark underflow, a truncated stream
//   too-large         medium    the stream is past the opcode or byte budget; the rest is unread
//   partial-parse     medium    a joblib stream broke after a NumpyArrayWrapper: joblib writes the array
//                               bytes inline, so the opcodes after the first array were not walked
import { Cursor, ScanTruncated, ScanMalformed, safeDetail } from "./model-scan-bytes.mjs";

// ---- the lists ----
// Exact module.name pairs (after py2 normalisation) that ordinary model pickles use.
const SAFE_EXACT = new Set([
  "collections.OrderedDict", "collections.defaultdict", "collections.deque", "collections.Counter", "collections.namedtuple",
  "copyreg._reconstructor", "copyreg.__newobj__", "copyreg.__newobj_ex__", "_codecs.encode",
  "builtins.set", "builtins.frozenset", "builtins.dict", "builtins.list", "builtins.tuple", "builtins.int", "builtins.float",
  "builtins.complex", "builtins.bytes", "builtins.bytearray", "builtins.str", "builtins.bool", "builtins.slice", "builtins.range",
  "builtins.object", "builtins.unicode", "builtins.long", "builtins.Ellipsis", "builtins.NotImplemented",
  "torch._tensor._rebuild_from_type_v2", "torch._tensor._rebuild_from_type", "torch.Size", "torch.device", "torch.dtype",
  "torch.memory_format", "torch.contiguous_format", "torch.channels_last", "torch.channels_last_3d", "torch.preserve_format",
  "torch.serialization._get_layout", "torch.strided", "torch.sparse_coo",
  "numpy.ndarray", "numpy.dtype", "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
  "numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar", "numpy.core.numeric._frombuffer", "numpy._core.numeric._frombuffer",
  "numpy.ma.core._mareconstruct", "numpy.random._pickle.__randomstate_ctor", "numpy.random._pickle.__generator_ctor",
  "numpy.random._pickle.__bit_generator_ctor",
  "joblib.numpy_pickle.NumpyArrayWrapper", "joblib.numpy_pickle_compat.NDArrayWrapper",
  "datetime.datetime", "datetime.date", "datetime.time", "datetime.timedelta", "datetime.timezone",
  "decimal.Decimal", "fractions.Fraction", "uuid.UUID", "argparse.Namespace", "re._compile",
  "pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePath", "pathlib.PurePosixPath", "pathlib.PureWindowsPath"
]);
const TORCH_DTYPES = /^(?:float(?:16|32|64)|bfloat16|half|double|int(?:8|16|32|64)|uint(?:8|16|32|64)|bool|complex(?:32|64|128)|cfloat|cdouble|qint8|quint8|qint32|quint4x2|float8_\w{1,12})$/;
const NUMPY_SCALARS = /^(?:float(?:16|32|64|128)|int(?:8|16|32|64)|uint(?:8|16|32|64)|bool_?|complex(?:64|128|256)|str_|bytes_|longlong|ulonglong|intc|uintc|half|single|double|longdouble|datetime64|timedelta64)$/;
// Module prefixes whose every name is a model-structure class or a tensor rebuild function.
const SAFE_PREFIX = ["torch.nn.", "torch.ao.nn.", "sklearn.", "xgboost.", "lightgbm."];

// Deny list. A module matches itself and its submodules (os → os.path). Sources: the denied-globals
// lists other static pickle scanners publish (picklescan, ModelScan, fickling), merged.
const DANGEROUS_MODULES = [
  "os", "posix", "nt", "subprocess", "_posixsubprocess", "socket", "sys", "shutil", "pty", "runpy", "importlib", "imp",
  "webbrowser", "requests", "urllib", "urllib2", "urllib3", "httplib", "http", "httpx", "aiohttp", "ftplib", "smtplib",
  "telnetlib", "ctypes", "_ctypes", "pickle", "_pickle", "cPickle", "dill", "cloudpickle", "marshal", "types", "code", "codeop",
  "commands", "popen2", "multiprocessing", "asyncio", "signal", "pdb", "bdb", "timeit", "cProfile", "profile", "trace",
  "doctest", "operator", "_operator", "functools", "pkgutil", "zipimport", "pip", "setuptools", "distutils", "inspect",
  "numpy.testing", "numpy.f2py", "torch.hub", "torch.jit", "torch._dynamo", "torch.utils.cpp_extension", "_io.FileIO",
  "io.FileIO"
];
const DANGEROUS_EXACT = new Set([
  "builtins.eval", "builtins.exec", "builtins.execfile", "builtins.compile", "builtins.getattr", "builtins.setattr",
  "builtins.delattr", "builtins.__import__", "builtins.open", "builtins.globals", "builtins.locals", "builtins.vars",
  "builtins.input", "builtins.breakpoint", "builtins.help", "builtins.exit", "builtins.quit", "builtins.apply",
  "builtins.file", "builtins.reload", "builtins.memoryview",
  "io.open", "_io.open", "codecs.open", "tempfile.mktemp"
]);
// Globals that deserialize a second payload (which this pass does not open).
const NESTED_LOAD = new Set([
  "torch.load", "torch.serialization.load", "torch.storage._load_from_bytes", "numpy.load", "joblib.load", "pandas.read_pickle",
  "pandas.io.pickle.read_pickle"
]);
const PY2 = { __builtin__: "builtins", copy_reg: "copyreg", __builtins__: "builtins", exceptions: "builtins" };

const underModule = (mod, list) => list.some((m) => mod === m || mod.startsWith(`${m}.`));

// → "safe" | "dangerous" | "nested" | "unknown"
export function classifyGlobal(module, name) {
  const mod = PY2[module] || module;
  const full = `${mod}.${name}`;
  if (DANGEROUS_EXACT.has(full) || underModule(mod, DANGEROUS_MODULES) || underModule(full, DANGEROUS_MODULES)) return "dangerous";
  if (NESTED_LOAD.has(full)) return "nested";
  if (SAFE_EXACT.has(full)) return "safe";
  // A dunder segment reaches interpreter internals (__globals__, __builtins__, __subclasses__) and a
  // dotted name on a path class is a method call with a chosen self (pathlib.Path.write_text).
  if (/(?:^|\.)__\w+__(?:\.|$)/.test(name) || /(?:^|\.)__\w+__(?:\.|$)/.test(mod)) return "dangerous";
  if (mod === "pathlib" && name.includes(".")) return "dangerous";
  if (mod === "torch" && (/Storage$/.test(name) || TORCH_DTYPES.test(name))) return "safe";
  if (mod === "torch._utils" && /^_rebuild_\w+$/.test(name)) return "safe";
  if (mod === "numpy" && NUMPY_SCALARS.test(name)) return "safe";
  if (SAFE_PREFIX.some((p) => full.startsWith(p))) return "safe";
  return "unknown";
}

// ---- the opcode table: byte → [name, argument kind] ----
// Argument kinds: n0 none, u1/u2/u4/i4/u8 fixed ints, f8 float, line one text line, line2 two text
// lines, s1/s4/s8 length-prefixed byte strings with a 1/4/8-byte length.
const OPS = {
  0x28: ["MARK", "n0"], 0x2e: ["STOP", "n0"], 0x30: ["POP", "n0"], 0x31: ["POP_MARK", "n0"], 0x32: ["DUP", "n0"],
  0x46: ["FLOAT", "line"], 0x49: ["INT", "line"], 0x4a: ["BININT", "i4"], 0x4b: ["BININT1", "u1"], 0x4c: ["LONG", "line"],
  0x4d: ["BININT2", "u2"], 0x4e: ["NONE", "n0"], 0x50: ["PERSID", "line"], 0x51: ["BINPERSID", "n0"], 0x52: ["REDUCE", "n0"],
  0x53: ["STRING", "line"], 0x54: ["BINSTRING", "s4"], 0x55: ["SHORT_BINSTRING", "s1"], 0x56: ["UNICODE", "line"],
  0x58: ["BINUNICODE", "s4"], 0x61: ["APPEND", "n0"], 0x62: ["BUILD", "n0"], 0x63: ["GLOBAL", "line2"], 0x64: ["DICT", "n0"],
  0x7d: ["EMPTY_DICT", "n0"], 0x65: ["APPENDS", "n0"], 0x67: ["GET", "line"], 0x68: ["BINGET", "u1"], 0x69: ["INST", "line2"],
  0x6a: ["LONG_BINGET", "u4"], 0x6c: ["LIST", "n0"], 0x5d: ["EMPTY_LIST", "n0"], 0x6f: ["OBJ", "n0"], 0x70: ["PUT", "line"],
  0x71: ["BINPUT", "u1"], 0x72: ["LONG_BINPUT", "u4"], 0x73: ["SETITEM", "n0"], 0x74: ["TUPLE", "n0"], 0x29: ["EMPTY_TUPLE", "n0"],
  0x75: ["SETITEMS", "n0"], 0x47: ["BINFLOAT", "f8"],
  0x80: ["PROTO", "u1"], 0x81: ["NEWOBJ", "n0"], 0x82: ["EXT1", "u1"], 0x83: ["EXT2", "u2"], 0x84: ["EXT4", "i4"],
  0x85: ["TUPLE1", "n0"], 0x86: ["TUPLE2", "n0"], 0x87: ["TUPLE3", "n0"], 0x88: ["NEWTRUE", "n0"], 0x89: ["NEWFALSE", "n0"],
  0x8a: ["LONG1", "s1"], 0x8b: ["LONG4", "s4"],
  0x42: ["BINBYTES", "s4"], 0x43: ["SHORT_BINBYTES", "s1"],
  0x8c: ["SHORT_BINUNICODE", "s1"], 0x8d: ["BINUNICODE8", "s8"], 0x8e: ["BINBYTES8", "s8"], 0x8f: ["EMPTY_SET", "n0"],
  0x90: ["ADDITEMS", "n0"], 0x91: ["FROZENSET", "n0"], 0x92: ["NEWOBJ_EX", "n0"], 0x93: ["STACK_GLOBAL", "n0"],
  0x94: ["MEMOIZE", "n0"], 0x95: ["FRAME", "u8"],
  0x96: ["BYTEARRAY8", "s8"], 0x97: ["NEXT_BUFFER", "n0"], 0x98: ["READONLY_BUFFER", "n0"]
};
export const PICKLE_OPCODES = Object.freeze(Object.fromEntries(Object.entries(OPS).map(([k, v]) => [Number(k), v[0]])));

export const PICKLE_LIMITS = Object.freeze({ maxOps: 20_000_000, maxBytes: 2 * 1024 ** 3, maxMemo: 1_000_000, maxStack: 1_000_000, maxPickles: 8, maxDetails: 40 });

const STR_KEEP = 512;
const MARK = Object.freeze({ t: "mark" });
const OPAQUE = Object.freeze({ t: "obj" });
const CALLED = Object.freeze({ t: "call" });
const memoKey = (a) => (typeof a === "number" ? a : /^\s*\d+\s*$/.test(a) ? Number(a) : a.trim());
const textOps = new Set(["STRING", "UNICODE", "BINSTRING", "SHORT_BINSTRING", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"]);

// Protocol-0 STRING is a Python repr ('os' or "os"); the others are raw.
function strValue(name, raw) {
  if (raw.length > STR_KEEP) return { t: "str", v: null };
  let s = name === "BINUNICODE" || name === "SHORT_BINUNICODE" || name === "BINUNICODE8" ? raw.toString("utf8") : raw.toString("latin1");
  if (name === "STRING") s = s.replace(/^(['"])(.*)\1$/s, "$2");
  if (name === "UNICODE") s = s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  return { t: "str", v: s };
}

// Walks every pickle in [start, end). → { findings, globals: [{ module, name, kind }], ops, protocol, pickles }
export function scanPickle(src, start = 0, end = src.size, limits = PICKLE_LIMITS) {
  const over = end - start > limits.maxBytes;
  const cur = new Cursor(src, start, over ? start + limits.maxBytes : end);
  const counts = new Map();   // class → { severity, count, details: Set }
  const globals = new Map();  // "mod.name" → { module, name, kind }
  let ops = 0, protocol = 0, pickles = 0;
  const add = (cls, severity, detail) => {
    let c = counts.get(cls);
    if (!c) counts.set(cls, (c = { severity, count: 0, details: new Set() }));
    c.count++;
    if (detail && c.details.size < limits.maxDetails) c.details.add(safeDetail(detail));
  };
  const noteGlobal = (module, name) => {
    const kind = classifyGlobal(module, name);
    const full = `${module}.${name}`;
    if (!globals.has(full) && globals.size < 10_000) globals.set(full, { module: safeDetail(module), name: safeDetail(name), kind });
    if (kind === "dangerous") add("dangerous-import", "critical", full);
    else if (kind === "nested") add("nested-load", "medium", full);
    else if (kind === "unknown") add("unknown-import", "low", full);
    return { t: "global", m: module, n: name, kind };
  };
  const call = (callable) => {
    if (!callable || callable.t !== "global") add("indirect-call", "high", callable && callable.t === "call" ? "callable is the result of a call" : "callable is not an imported global");
    return CALLED;
  };

  let complete = false;
  try {
    while (cur.left > 0 && pickles < limits.maxPickles) {
      // A second pickle follows the first only in the legacy torch layout (each one starts with PROTO).
      if (pickles > 0 && src.read(cur.pos, 1)[0] !== 0x80) break;
      pickles++;
      const stack = [];
      const memo = new Map();
      const pop = () => { if (!stack.length) throw new ScanMalformed("stack underflow"); return stack.pop(); };
      const popMark = () => {
        let i = stack.length - 1;
        while (i >= 0 && stack[i] !== MARK) i--;
        if (i < 0) throw new ScanMalformed("mark not found");
        return stack.splice(i).slice(1);
      };
      const push = (v) => { if (stack.length >= limits.maxStack) throw new ScanMalformed("stack too deep"); stack.push(v); };
      let stopped = false;
      while (!stopped) {
        if (++ops > limits.maxOps) { add("too-large", "medium", "opcode budget reached"); return finish(false); }
        const op = cur.u8();
        const def = OPS[op];
        if (!def) throw new ScanMalformed(`unknown opcode 0x${op.toString(16)}`);
        const [name, kind] = def;
        let arg = null;
        switch (kind) {
          case "u1": arg = cur.u8(); break;
          case "u2": arg = cur.u16(); break;
          case "u4": arg = cur.u32(); break;
          case "i4": arg = cur.i32(); break;
          case "u8": arg = cur.u64(); break;
          case "f8": cur.skip(8); break;
          case "line": arg = cur.line(); break;
          case "line2": arg = [cur.line(), cur.line()]; break;
          case "s1": case "s4": case "s8": {
            const n = kind === "s1" ? cur.u8() : kind === "s4" ? cur.i32() : cur.u64();
            if (n < 0) throw new ScanMalformed("negative length");
            if (textOps.has(name) && n <= STR_KEEP) arg = cur.bytes(n);
            else cur.skip(n);
            break;
          }
          default: break;
        }
        switch (name) {
          case "PROTO": protocol = Math.max(protocol, arg); break;
          case "FRAME": break;
          case "STOP": stopped = true; break;
          case "MARK": push(MARK); break;
          case "POP": if (stack.length && stack[stack.length - 1] === MARK) stack.pop(); else pop(); break;
          case "POP_MARK": popMark(); break;
          case "DUP": { const v = pop(); push(v); push(v); break; }
          case "GLOBAL": push(noteGlobal(arg[0], arg[1])); break;
          case "STACK_GLOBAL": {
            const n = pop(), m = pop();
            if (m.t === "str" && n.t === "str" && m.v != null && n.v != null) push(noteGlobal(m.v, n.v));
            else { add("unresolved-global", "medium", "STACK_GLOBAL with a non-constant module or name"); push({ t: "global", m: "?", n: "?", kind: "unresolved" }); }
            break;
          }
          case "EXT1": case "EXT2": case "EXT4": add("unresolved-global", "medium", `extension code ${arg}`); push({ t: "global", m: "?", n: "?", kind: "unresolved" }); break;
          case "INST": { noteGlobal(arg[0], arg[1]); popMark(); push(CALLED); break; }
          case "OBJ": { const items = popMark(); if (!items.length) throw new ScanMalformed("OBJ without a class"); call(items[0]); push(CALLED); break; }
          case "REDUCE": { pop(); const c = pop(); push(call(c)); break; }
          case "NEWOBJ": { pop(); const c = pop(); push(call(c)); break; }
          case "NEWOBJ_EX": { pop(); pop(); const c = pop(); push(call(c)); break; }
          case "BUILD": pop(); if (!stack.length) throw new ScanMalformed("BUILD without a target"); break;
          case "BINPERSID": pop(); push(OPAQUE); break;
          case "PERSID": push(OPAQUE); break;
          case "PUT": case "BINPUT": case "LONG_BINPUT": case "MEMOIZE": {
            if (!stack.length || stack[stack.length - 1] === MARK) throw new ScanMalformed("memo store on an empty stack");
            const key = name === "MEMOIZE" ? memo.size : memoKey(arg);
            if (memo.size < limits.maxMemo || memo.has(key)) memo.set(key, stack[stack.length - 1]);
            break;
          }
          case "GET": case "BINGET": case "LONG_BINGET": {
            const key = memoKey(arg);
            if (!memo.has(key)) throw new ScanMalformed("memo key not found");
            push(memo.get(key));
            break;
          }
          case "APPEND": pop(); break;
          case "APPENDS": case "SETITEMS": case "ADDITEMS": popMark(); break;
          case "SETITEM": pop(); pop(); break;
          case "TUPLE": case "LIST": case "DICT": case "FROZENSET": popMark(); push(OPAQUE); break;
          case "TUPLE1": pop(); push(OPAQUE); break;
          case "TUPLE2": pop(); pop(); push(OPAQUE); break;
          case "TUPLE3": pop(); pop(); pop(); push(OPAQUE); break;
          case "READONLY_BUFFER": pop(); push(OPAQUE); break;
          default:
            if (!textOps.has(name)) push(OPAQUE);
            else if (arg == null) push({ t: "str", v: null });
            else push(strValue(name, typeof arg === "string" ? Buffer.from(arg, "latin1") : arg));
        }
      }
    }
    complete = true;
  } catch (e) {
    // joblib writes numpy array bytes straight into the stream after each NumpyArrayWrapper, so a walk
    // that stops there has not seen the rest: reported as a partial parse, not as a broken file.
    const joblib = globals.has("joblib.numpy_pickle.NumpyArrayWrapper");
    if (e instanceof ScanTruncated && over) add("too-large", "medium", "pickle past the byte budget");
    else if (joblib && (e instanceof ScanTruncated || e instanceof ScanMalformed)) add("partial-parse", "medium", "joblib inline array data; opcodes after it were not walked");
    else if (e instanceof ScanTruncated) add("malformed", "medium", "truncated pickle stream");
    else if (e instanceof ScanMalformed) add("malformed", "medium", e.message);
    else throw e;
  }
  return finish(complete);

  function finish(done) {
    if (pickles === 0 && !counts.has("malformed")) add("malformed", "medium", "empty pickle stream");
    const findings = [...counts.entries()].map(([cls, c]) => ({ class: cls, severity: c.severity, count: c.count, details: [...c.details] }));
    return { findings, globals: [...globals.values()], ops, protocol, pickles, complete: done };
  }
}

// A pickle stream starts with PROTO (protocol 2+) or, for protocol 0/1, with an opcode such as MARK,
// EMPTY_DICT, EMPTY_LIST, GLOBAL or ( . Sniffing is only used to route extension-less files.
export function looksLikePickle(head) {
  if (!head || head.length < 2) return false;
  if (head[0] === 0x80 && head[1] >= 2 && head[1] <= 5) return true;
  return false;
}
