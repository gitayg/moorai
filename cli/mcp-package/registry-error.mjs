// The error every package fetch throws: `code` is a short content-free reason (network-error, timeout,
// http-404, offline, too-large …) that ends up in a report note as registry-<code> / download-<code>.
export class RegistryError extends Error {
  constructor(code) { super(code); this.code = code; }
}
