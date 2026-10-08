// Windows AI platform inventory (cli/local-ai-windows.mjs): Windows App SDK runtime packages, Windows
// ML execution-provider packages, Aion preview, NPU presence (ComputeAccelerator class) and the GPU
// class Windows ML's GPU execution providers document. Driven by captured-shape PowerShell JSON — no
// Windows machine is needed or used.
//
//   node --test test/local-ai-inventory-windows.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseWindowsAi, windowsAiPlatform, gpuTier, vendorOf, WIN_AI_PS } from "../cli/local-ai-windows.mjs";
import { localAiInventory } from "../cli/local-ai-inventory.mjs";

const PS_COPILOT_PLUS = JSON.stringify({
  p: [
    { n: "Microsoft.WindowsAppRuntime.1.8", v: "8000.616.304.0" },
    { n: "Microsoft.WindowsAppRuntime.1.8", v: "8000.616.304.0" },
    { n: "MicrosoftCorporationII.WinAppRuntime.Main.1.8", v: "8000.616.304.0" },
    { n: "MicrosoftCorporationII.WinAppRuntime.Singleton", v: "8000.616.304.0" },
    { n: "Microsoft.WinAppRuntime.DDLM.8000.616.304.0-a6", v: "8000.616.304.0" },
    { n: "MicrosoftCorporationII.WinML.Qualcomm.QNN.EP.1.8", v: "1.8.27.0" },
    { n: "Microsoft.WinML.ONNX.WebGPU.EP.2", v: "0.4.0.0" },
    { n: "Microsoft.AionInstructPreview.Framework.1.0", v: "1.0.12.0" }
  ],
  g: [{ n: "Qualcomm(R) Adreno(TM) X1-85 GPU", m: "Qualcomm Incorporated" }],
  a: [{ n: "Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Hexagon(TM) NPU", m: "Qualcomm Technologies, Inc." }]
});

test("packages: grouped into App SDK runtime / Windows ML EPs / Aion preview; duplicates collapsed; EP named", () => {
  const w = parseWindowsAi(PS_COPILOT_PLUS);
  assert.deepEqual(w.appSdkRuntime.map((p) => p.name), [
    "Microsoft.WindowsAppRuntime.1.8", "MicrosoftCorporationII.WinAppRuntime.Main.1.8", "MicrosoftCorporationII.WinAppRuntime.Singleton", "Microsoft.WinAppRuntime.DDLM.8000.616.304.0-a6"
  ]);
  assert.deepEqual(w.windowsMlEps, [
    { name: "MicrosoftCorporationII.WinML.Qualcomm.QNN.EP.1.8", version: "1.8.27.0", ep: "QNN" },
    { name: "Microsoft.WinML.ONNX.WebGPU.EP.2", version: "0.4.0.0", ep: "WebGPU" }
  ]);
  assert.deepEqual(w.aionPreview, [{ name: "Microsoft.AionInstructPreview.Framework.1.0", version: "1.0.12.0" }]);
});

test("NPU: a ComputeAccelerator device → present with vendor; none → absent", () => {
  assert.deepEqual(parseWindowsAi(PS_COPILOT_PLUS).npu, { present: true, count: 1, vendors: ["qualcomm"] });
  assert.equal(parseWindowsAi(PS_COPILOT_PLUS).localInference.npu, true);
  const intel = parseWindowsAi(JSON.stringify({ p: [], g: [], a: { n: "Intel(R) AI Boost", m: "Intel Corporation" } }));
  assert.deepEqual(intel.npu, { present: true, count: 1, vendors: ["intel"] }, "a single PowerShell object (not an array) still counts");
  const none = parseWindowsAi(JSON.stringify({ p: [], g: [], a: [] }));
  assert.deepEqual(none.npu, { present: false, count: 0, vendors: [] });
  assert.deepEqual(none.localInference, { npu: false, suitedGpu: false });
});

test("GPU class: the floors Windows ML documents (RTX 30xx+, RDNA 3+), Intel Arc; virtual adapters dropped", () => {
  const cases = [
    ["NVIDIA GeForce RTX 4070 Laptop GPU", "NVIDIA", "nvidia-rtx30plus"],
    ["NVIDIA GeForce RTX 3050 Ti", "NVIDIA", "nvidia-rtx30plus"],
    ["NVIDIA RTX A4000", "NVIDIA", "nvidia-rtx30plus"],
    ["NVIDIA GeForce RTX 2080", "NVIDIA", "nvidia-other"],
    ["NVIDIA GeForce GTX 1660", "NVIDIA", "nvidia-other"],
    ["AMD Radeon RX 7900 XTX", "Advanced Micro Devices, Inc.", "amd-rdna3plus"],
    ["AMD Radeon RX 9070", "Advanced Micro Devices, Inc.", "amd-rdna3plus"],
    ["AMD Radeon 780M Graphics", "Advanced Micro Devices, Inc.", "amd-rdna3plus"],
    ["AMD Radeon RX 6800", "Advanced Micro Devices, Inc.", "amd-other"],
    ["Intel(R) Arc(TM) A770 Graphics", "Intel Corporation", "intel-arc"],
    ["Intel(R) UHD Graphics 620", "Intel Corporation", "intel-other"],
    ["Qualcomm(R) Adreno(TM) X1-85 GPU", "Qualcomm", "qualcomm"],
    ["Microsoft Basic Display Adapter", "(Standard display types)", "virtual"]
  ];
  for (const [n, m, tier] of cases) assert.equal(gpuTier(n, m), tier, n);
  const w = parseWindowsAi(JSON.stringify({ p: [], a: [], g: [{ n: "NVIDIA GeForce RTX 4070", m: "NVIDIA" }, { n: "Microsoft Basic Display Adapter", m: "(Standard display types)" }] }));
  assert.deepEqual(w.gpus, [{ vendor: "nvidia", tier: "nvidia-rtx30plus" }]);
  assert.deepEqual(w.localInference, { npu: false, suitedGpu: true });
  assert.equal(vendorOf("Parallels Display Adapter (WDDM)", "Parallels"), "virtual");
});

test("content-free: device names classify only; unrelated or malformed packages and versions are dropped", () => {
  const w = parseWindowsAi(JSON.stringify({
    p: [{ n: "Microsoft.WindowsAppRuntime.1.8", v: "not-a-version" }, { n: "Contoso.SecretApp", v: "1.0.0.0" }, { n: "Microsoft.WinML.<script>", v: "1.0" }],
    g: [{ n: "NVIDIA GeForce RTX 4090 (asset-tag DEV-ALICE-01)", m: "NVIDIA" }],
    a: [{ n: "Intel(R) AI Boost", m: "Intel Corporation" }]
  }));
  assert.deepEqual(w.appSdkRuntime, [{ name: "Microsoft.WindowsAppRuntime.1.8", version: null }]);
  assert.deepEqual(w.windowsMlEps, []);
  const s = JSON.stringify(w);
  for (const leak of ["Contoso", "ALICE", "AI Boost", "4090", "script"]) assert.ok(!s.includes(leak), leak);
});

test("probe: one non-admin PowerShell call with a 10 s budget; unusable output or no PowerShell → null", () => {
  const calls = [];
  const runner = (cmd, args, timeout) => { calls.push({ cmd, args, timeout }); return PS_COPILOT_PLUS; };
  assert.ok(windowsAiPlatform(runner));
  assert.deepEqual(calls, [{ cmd: "powershell", args: ["-NoProfile", "-NonInteractive", "-Command", WIN_AI_PS], timeout: 10000 }]);
  assert.match(WIN_AI_PS, /Get-AppxPackage/);
  assert.match(WIN_AI_PS, /Get-PnpDevice -Class ComputeAccelerator -PresentOnly/);
  assert.doesNotMatch(WIN_AI_PS, /-AllUsers|RunAs|Start-Process|Set-|Remove-|Invoke-WebRequest/i, "read-only, current user, no elevation");
  assert.equal(windowsAiPlatform(() => null), null);
  assert.equal(windowsAiPlatform(() => "WARNING: not json"), null);
});

test("Windows only: the PowerShell probe never runs on macOS or Linux", () => {
  for (const platform of ["darwin", "linux"]) {
    const cmds = [];
    const inv = localAiInventory({ runner: (cmd) => { cmds.push(cmd); return null; }, platform, env: {}, home: "/none", exists: () => false, readFile: () => { throw new Error("x"); } });
    assert.equal(inv.windowsAi, null);
    assert.ok(!cmds.includes("powershell"), platform);
  }
  const win = localAiInventory({ runner: (cmd) => (cmd === "powershell" ? PS_COPILOT_PLUS : null), platform: "win32", env: {}, home: "C:/none", exists: () => false, readFile: () => { throw new Error("x"); } });
  assert.equal(win.windowsAi.npu.present, true);
});
