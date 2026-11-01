// TEST-ONLY preload for test/mcp-server-sandbox-guard.test.mjs: the stdio guard believes it runs on Linux
// (process.platform "linux"), where mcpServerSandbox has no backend. Loaded with `node --import`, never by
// the guard itself, which has no platform knob and must not get one: a switch that makes the guard think it
// is not on macOS would be a switch that turns the sandbox off.
Object.defineProperty(process, "platform", { value: "linux", configurable: true, enumerable: true, writable: false });
