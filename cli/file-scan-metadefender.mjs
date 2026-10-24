export const NAME = "metadefender";
export function createMetaDefender() { return { name: NAME, lookup: async () => ({ state: "unknown" }), upload: async () => ({ id: "" }), poll: async () => ({ state: "pending" }) }; }
export function parseReport() { return { state: "unknown" }; }
