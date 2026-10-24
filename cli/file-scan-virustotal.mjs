export const NAME = "virustotal";
export function createVirusTotal() { return { name: NAME, lookup: async () => ({ state: "unknown" }), upload: async () => ({ id: "" }), poll: async () => ({ state: "pending" }) }; }
export function parseFile() { return { state: "unknown" }; }
export function parseAnalysis() { return { state: "pending" }; }
