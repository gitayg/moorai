// Windows AI platform inventory (Windows only), for cli/local-ai-inventory.mjs. ONE PowerShell call,
// no admin rights, 10 s timeout, fail-open to null. Emits Microsoft package names + versions, NPU
// presence and vendor, and a GPU CLASS per adapter. The GPU / NPU friendly names are read only to
// classify them and are never emitted.
//
// Package families, from Microsoft's docs:
//   Windows App SDK runtime — github.com/microsoft/WindowsAppSDK specs/Deployment/MSIXPackages.md:
//     Framework "Microsoft.WindowsAppRuntime[.SubName].<Major>[-VersionTag]…", Main
//     "MicrosoftCorporationII.WinAppRuntime.Main.<ReleaseMajor>…", Singleton
//     "MicrosoftCorporationII.WinAppRuntime.Singleton…", DDLM "Microsoft.WinAppRuntime.DDLM.<Version>-<Arch>…".
//   Windows ML execution providers — learn.microsoft.com/windows/ai/new-windows-ml/versioning:
//     `Get-AppxPackage MicrosoftCorporationII.WinML.*` → e.g. "MicrosoftCorporationII.WinML.Qualcomm.QNN.EP.1.8";
//     supported-execution-providers: WebGPU EP family "Microsoft.WinML.ONNX.WebGPU.EP.2". CPU and DirectML
//     ship inside Windows ML itself and have no package of their own.
//   Aion Instruct preview — github.com/microsoft/Aion-Instruct-Preview-Sample:
//     "Microsoft.AionInstructPreview.Framework.1.0_8wekyb3d8bbwe".
// NPU — learn.microsoft.com/windows-hardware/drivers/display/mcdm-implementation-guidelines: "MCDM
//   devices belong to the ComputeAccelerator class" (ClassGuid F01A9D53-3FF6-48D2-9F97-C8A7004BE10C).
// GPU class — the hardware floors Windows ML documents for its GPU execution providers
//   (supported-execution-providers): NvTensorRtRtx "NVIDIA GeForce RTX 30XX and above"; MIGraphX "AMD
//   RDNA 3 or later GPU". Intel Arc is classed for OpenVINO by inference (Intel's own page, not quoted).

export const WIN_AI_PS = [
  "$ErrorActionPreference='SilentlyContinue'",
  "$re='^(Microsoft\\.WindowsAppRuntime\\.|MicrosoftCorporationII\\.WinAppRuntime\\.|Microsoft\\.WinAppRuntime\\.DDLM\\.|MicrosoftCorporationII\\.WinML\\.|Microsoft\\.WinML\\.|Microsoft\\.AionInstructPreview\\.)'",
  "$p=@(Get-AppxPackage | Where-Object { $_.Name -match $re } | ForEach-Object { @{n=[string]$_.Name;v=[string]$_.Version} })",
  "$g=@(Get-CimInstance -ClassName Win32_VideoController | ForEach-Object { @{n=[string]$_.Name;m=[string]$_.AdapterCompatibility} })",
  "$a=@(Get-PnpDevice -Class ComputeAccelerator -PresentOnly | ForEach-Object { @{n=[string]$_.FriendlyName;m=[string]$_.Manufacturer} })",
  "ConvertTo-Json -Compress -Depth 4 -InputObject @{p=$p;g=$g;a=$a}"
].join("; ");

const PKG_NAME = /^[A-Za-z0-9.-]{1,128}$/;
const PKG_VERSION = /^\d+(\.\d+){0,3}$/;
const GROUPS = [
  [/^(Microsoft\.WindowsAppRuntime\.|MicrosoftCorporationII\.WinAppRuntime\.|Microsoft\.WinAppRuntime\.DDLM\.)/i, "appSdkRuntime"],
  [/^(MicrosoftCorporationII\.WinML\.|Microsoft\.WinML\.)/i, "windowsMlEps"],
  [/^Microsoft\.AionInstructPreview\./i, "aionPreview"]
];
const EP_OF = [[/QNN/i, "QNN"], [/OpenVINO/i, "OpenVINO"], [/VitisAI|AMD\.NPU/i, "VitisAI"], [/MIGraphX|AMD\.GPU/i, "MIGraphX"], [/NVIDIA|TensorRT|TRT/i, "NvTensorRtRtx"], [/WebGPU/i, "WebGPU"]];

export function vendorOf(name, maker) {
  const s = `${name || ""} ${maker || ""}`;
  if (/microsoft basic|remote display|hyper-v|vmware|virtualbox|parallels|citrix|indirect display/i.test(s)) return "virtual";
  if (/nvidia/i.test(s)) return "nvidia";
  if (/\bamd\b|advanced micro devices|radeon/i.test(s)) return "amd";
  if (/intel/i.test(s)) return "intel";
  if (/qualcomm|snapdragon|adreno|hexagon/i.test(s)) return "qualcomm";
  return "other";
}

// → nvidia-rtx30plus | nvidia-other | amd-rdna3plus | amd-other | intel-arc | intel-other | qualcomm | virtual | other
export function gpuTier(name, maker) {
  const v = vendorOf(name, maker), n = String(name || "");
  if (v === "nvidia") {
    const m = n.match(/RTX\s*(\d{2})\d{2}\b/i);
    if ((m && Number(m[1]) >= 30) || /RTX\s*(A\d{3,4}|PRO|\d{4}\s*Ada)/i.test(n)) return "nvidia-rtx30plus";
    return "nvidia-other";
  }
  if (v === "amd") {
    const m = n.match(/\bRX\s*(\d)\d{3}\b/i);
    if ((m && Number(m[1]) >= 7) || /Radeon\s*(7[4-9]0M|8[0-9]0M)\b/i.test(n)) return "amd-rdna3plus";
    return "amd-other";
  }
  if (v === "intel") return /\bArc\b/i.test(n) ? "intel-arc" : "intel-other";
  return v;
}
const SUITED = new Set(["nvidia-rtx30plus", "amd-rdna3plus", "intel-arc"]);

const asArr = (x) => (Array.isArray(x) ? x : x && typeof x === "object" ? [x] : []);

// PowerShell JSON → the content-free platform record, or null when the probe produced nothing usable.
export function parseWindowsAi(jsonText) {
  let j;
  try { j = JSON.parse(String(jsonText || "").trim()); } catch { return null; }
  if (!j || typeof j !== "object") return null;
  const out = { appSdkRuntime: [], windowsMlEps: [], aionPreview: [] };
  const seen = new Set();
  for (const p of asArr(j.p)) {
    const name = typeof p.n === "string" ? p.n : "", version = typeof p.v === "string" && PKG_VERSION.test(p.v) ? p.v : null;
    if (!PKG_NAME.test(name) || seen.has(`${name}|${version}`)) continue;
    seen.add(`${name}|${version}`);
    const g = GROUPS.find(([re]) => re.test(name));
    if (!g) continue;
    const row = { name, version };
    if (g[1] === "windowsMlEps") row.ep = (EP_OF.find(([re]) => re.test(name)) || [, "unknown"])[1];
    out[g[1]].push(row);
  }
  const npus = asArr(j.a).map((d) => vendorOf(d.n, d.m));
  const gpus = asArr(j.g).map((d) => ({ vendor: vendorOf(d.n, d.m), tier: gpuTier(d.n, d.m) })).filter((g) => g.vendor !== "virtual");
  out.npu = { present: npus.length > 0, count: npus.length, vendors: [...new Set(npus)].sort() };
  out.gpus = gpus;
  out.localInference = { npu: npus.length > 0, suitedGpu: gpus.some((g) => SUITED.has(g.tier)) };
  return out;
}

export function windowsAiPlatform(runner) {
  const txt = runner("powershell", ["-NoProfile", "-NonInteractive", "-Command", WIN_AI_PS], 10000);
  return txt == null ? null : parseWindowsAi(txt);
}

// Windows On-device Agent Registry (ODR): the MCP "agent connectors" registered with Windows, reported
// as names + two booleans and a count. Never a command, an argument, a path, a URI or a package id.
//   Command — learn.microsoft.com/windows/ai/mcp/quickstart-mcp-host: "List the available MCP servers
//     executing the command line call `odr.exe list`. This command returns the list of servers in JSON
//     format". Requires "Windows build 26220.7262 or higher" (same page); older builds have no odr.exe,
//     which is reported as no block at all (fail-open).
//   Shape — two documented forms, both accepted:
//     (a) Learn quickstart: `JSON.parse(stdout)` is the server list; each entry carries
//         `server.manifest?.server?.mcp_config?.command`, the manifest being an MCP bundle manifest
//         (`name`, `server`, `_meta`) — learn.microsoft.com/windows/ai/mcp/servers/mcp-containment.
//     (b) github.com/microsoft/mcp-on-windows-samples @ 70e11f7, mcp-client-js/app.js:
//         `servers.structuredContent.servers`, each `server.server?.name` and
//         `server.server?.packages?.[0]?.identifier` (the id passed to `odr.exe mcp run --proxy`).
//     (b)'s `packages[]` with `registryType` / `identifier`, and `remotes[]`, are the MCP registry
//     server.json fields (github.com/modelcontextprotocol/registry @ 9cbf0b3,
//     docs/reference/server-json/generic-server-json.md).
//   packaged / contained — NOT a field in any documented output, so both are derived:
//     packaged  = a package whose identifier is shaped like a Package Family Name (<Name>_<13-char
//                 publisher id>, as in "…Framework.1.0_8wekyb3d8bbwe"), or whose registryType says
//                 msix/appx (no such registryType is documented; it is accepted, not expected).
//     contained = packaged and no `remotes`. mcp-containment: "Any packaged apps with identity will always
//                 run in a contained session in this preview"; "Servers which are packaged with MCP
//                 bundles currently cannot run contained"; a remote server (`odr.exe mcp add --uri`,
//                 learn.microsoft.com/windows/ai/mcp/servers/mcp-manual) runs nowhere on the device.
//   Both derivations are unverified against a real `odr.exe list` (no Windows 26220.7262+ machine used).
export const ODR_ARGV = ["odr.exe", ["list"]];
const ODR_MAX_ITEMS = 100;
const PFN = /^[A-Za-z0-9.-]{3,50}_[0-9a-hjkmnp-tv-z]{13}$/;
const isObj = (x) => !!x && typeof x === "object" && !Array.isArray(x);

// A connector NAME only: control characters stripped, capped, and refused when it looks like a path or URL.
export function odrName(v) {
  if (typeof v !== "string") return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 128);
  if (!s || /\\|:\/\/|^[A-Za-z]:|^[\/~]/.test(s)) return null;
  return s;
}

export function parseOdrList(text) {
  let j;
  try { j = JSON.parse(String(text || "").trim()); } catch { return null; }
  const list = Array.isArray(j) ? j : isObj(j) && isObj(j.structuredContent) && Array.isArray(j.structuredContent.servers) ? j.structuredContent.servers : isObj(j) && Array.isArray(j.servers) ? j.servers : null;
  if (!list) return null;
  const entries = list.filter(isObj);
  const items = entries.slice(0, ODR_MAX_ITEMS).map((e) => {
    const srv = isObj(e.server) ? e.server : {}, man = isObj(e.manifest) ? e.manifest : {};
    const name = odrName(srv.name) ?? odrName(man.name) ?? odrName(e.name);
    const pkgs = [srv.packages, e.packages].find(Array.isArray) || [];
    const remotes = [srv.remotes, e.remotes].find(Array.isArray) || [];
    const remote = remotes.length > 0;
    const packaged = pkgs.some((p) => isObj(p) && ((typeof p.registryType === "string" && /^(msix|appx)$/i.test(p.registryType)) || (typeof p.identifier === "string" && PFN.test(p.identifier))));
    return { name, packaged, contained: packaged && !remote };
  });
  return { count: entries.length, items };
}

export function odrAgentConnectors(runner) {
  const txt = runner(ODR_ARGV[0], ODR_ARGV[1], 5000);
  return txt == null ? null : parseOdrList(txt);
}
