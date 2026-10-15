// TEST-ONLY preload for test/containment-enforce-hook.test.mjs: the hook process believes it runs on
// Windows 11 build 26100 (process.platform "win32", os.release() "10.0.26100"). Loaded with `node --import`,
// never by the hook itself, which has no platform knob and must not get one: a switch that makes the hook
// think it is not on Windows would be a switch that turns MXC enforcement off.
// Everything else stays real: reg.exe does not exist here, so the registry UBR reads as unknown (null).
import os from "node:os";

Object.defineProperty(process, "platform", { value: "win32", configurable: true, enumerable: true, writable: false });
os.release = () => "10.0.26100";
