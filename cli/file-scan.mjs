export { FileScanError } from "./file-scan-http.mjs";
export function createFileScanner() { return { scan: async () => ({ verdict: "error" }), stats: () => ({}) }; }
export function fileScanDecision() { return { action: "allow" }; }
export function fileScanAlert() { return {}; }
export function mimeClass() { return "other"; }
export function sizeBucket() { return ""; }
