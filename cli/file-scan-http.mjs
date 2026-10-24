export class FileScanError extends Error { constructor(kind) { super(kind); this.kind = kind; } }
export async function call() { throw new FileScanError("network"); }
